import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";

import { DetectionExplorerClient } from "../src/client.js";
import { createServer } from "../src/server.js";

type Route = (url: URL) => unknown | Response;

async function connect(routes: Record<string, Route>) {
  const requested: URL[] = [];
  const fetch = async (raw: string) => {
    const url = new URL(raw);
    requested.push(url);
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const route = routes[path];
    if (!route) return new Response(JSON.stringify({ detail: "Not Found" }), { status: 404 });
    const body = route(url);
    return body instanceof Response ? body : new Response(JSON.stringify(body), { status: 200 });
  };
  const server = createServer(new DetectionExplorerClient({ fetch, sleep: async () => {} }));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server, requested };
}

const text = (result: unknown) => {
  const content = (result as { content: Array<{ type: string; text: string }> }).content;
  return content[0].text;
};

let open: Array<{ close: () => Promise<void> }> = [];
afterEach(async () => {
  await Promise.all(open.map((c) => c.close()));
  open = [];
});

describe("tool catalog", () => {
  it("exposes the documented read-only tools", async () => {
    const { client } = await connect({});
    open.push(client);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "actor_coverage",
      "actor_navigator_layer",
      "compare_detections",
      "corpus_overview",
      "coverage_gap",
      "find_related_detections",
      "get_detection",
      "observable_lookup",
      "query_language",
      "search_detections",
      "technique_coverage",
      "whats_new",
    ]);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(true);
      expect(tool.description?.length, tool.name).toBeGreaterThan(40);
    }
  });
});

describe("search_detections", () => {
  it("maps arguments onto the API and returns slim rows", async () => {
    const { client, requested } = await connect({
      "/detections": () => ({ total: 1, items: [{ id: "r1", title: "T", source: "sigma", mitre_techniques: ["T1055"] }] }),
    });
    open.push(client);
    const result = await client.callTool({
      name: "search_detections",
      arguments: { query: "tech:T1055", sources: ["sigma"], no_equivalent_in: ["elastic"], techniques: ["t1055"], limit: 5 },
    });
    const params = requested[0].searchParams;
    expect(params.get("q")).toBe("tech:T1055");
    expect(params.get("sources")).toBe("sigma");
    expect(params.get("no_equivalent_in")).toBe("elastic");
    expect(params.get("mitre_techniques")).toBe("T1055");
    expect(params.get("sort_by")).toBe("relevance");
    expect(params.get("limit")).toBe("5");
    const body = JSON.parse(text(result));
    expect(body.total).toBe(1);
    expect(body.results[0].url).toBe("https://detectionexplorer.io/detections/r1");
  });

  it("sorts newest first without a query", async () => {
    const { client, requested } = await connect({ "/detections": () => ({ total: 0, items: [] }) });
    open.push(client);
    await client.callTool({ name: "search_detections", arguments: {} });
    expect(requested[0].searchParams.get("sort_by")).toBe("rule_created_date");
    expect(requested[0].searchParams.get("sort_order")).toBe("desc");
  });

  it("rejects an unknown source before calling the API", async () => {
    const { client, requested } = await connect({});
    open.push(client);
    const result = await client.callTool({ name: "search_detections", arguments: { sources: ["crowdstrike"] } });
    expect(result.isError).toBe(true);
    expect(requested).toHaveLength(0);
  });
});

describe("errors", () => {
  it("returns API failures as tool errors the model can read", async () => {
    const { client } = await connect({});
    open.push(client);
    const result = await client.callTool({ name: "get_detection", arguments: { id: "missing" } });
    expect(result.isError).toBe(true);
    expect(text(result)).toContain("HTTP 404: Not Found");
  });
});

describe("actor_coverage", () => {
  it("resolves a name through the catalog and scopes coverage", async () => {
    const { client, requested } = await connect({
      "/actors": () => ({ items: [{ id: "G0016", name: "APT29" }, { id: "G9999", name: "Other" }] }),
      "/actors/G0016": () => ({ id: "G0016", name: "APT29", techniques: [], rules: [] }),
    });
    open.push(client);
    const result = await client.callTool({ name: "actor_coverage", arguments: { actor: "Cozy Bear", sources: ["elastic"] } });
    expect(requested[0].searchParams.get("q")).toBe("Cozy Bear");
    const detail = requested[1];
    expect(detail.pathname).toBe("/api/v1/actors/G0016");
    expect(detail.searchParams.get("sources")).toBe("elastic");
    expect(detail.searchParams.get("coverage")).toBe("strict");
    expect(JSON.parse(text(result)).other_matches_for_query).toEqual(["G9999 Other"]);
  });

  it("passes the scoped named rules through as the API returns them", async () => {
    // Since #170 the API narrows the rule list to `sources` itself; the
    // tool must not second-guess or trim what comes back.
    const { client, requested } = await connect({
      "/actors/G0016": () => ({
        id: "G0016",
        name: "APT29",
        techniques: [],
        rules: [
          { id: "a", title: "A", source: "sigma" },
          { id: "b", title: "B", source: "elastic" },
        ],
      }),
    });
    open.push(client);
    const result = await client.callTool({ name: "actor_coverage", arguments: { actor: "G0016", sources: ["sigma", "elastic"] } });
    const body = JSON.parse(text(result));
    expect(requested[0].searchParams.get("sources")).toContain("sigma");
    expect(body.named_rules.map((r: { id: string }) => r.id)).toEqual(["a", "b"]);
    expect(body).not.toHaveProperty("named_rules_outside_scope");
  });

  it("uses an ATT&CK ID directly and routes software layers", async () => {
    const { client, requested } = await connect({ "/software/S0154/navigator-layer": () => ({ name: "layer" }) });
    open.push(client);
    const result = await client.callTool({ name: "actor_navigator_layer", arguments: { actor: "s0154" } });
    expect(requested).toHaveLength(1);
    expect(JSON.parse(text(result))).toEqual({ name: "layer" });
  });

  it("says so when nothing matches", async () => {
    const { client } = await connect({ "/actors": () => ({ items: [] }) });
    open.push(client);
    const result = await client.callTool({ name: "actor_coverage", arguments: { actor: "Nobody" } });
    expect(result.isError).toBe(true);
    expect(text(result)).toContain('No ATT&CK group or software matches "Nobody"');
  });
});
