import { describe, expect, it } from "vitest";

import { ApiError, DetectionExplorerClient, USER_AGENT } from "../src/client.js";

type Call = { url: string; init?: RequestInit };

function fakeFetch(responses: Array<() => Response>) {
  const calls: Call[] = [];
  const fetch = async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    return next();
  };
  return { fetch, calls };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => () =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

describe("url", () => {
  const client = new DetectionExplorerClient({ baseUrl: "https://example.test/api/v1/" });

  it("joins arrays with commas and drops empty values", () => {
    const url = client.url("/detections", {
      q: "tech:T1055 source:sigma",
      sources: ["sigma", "elastic"],
      severities: [],
      offset: 0,
      building_block: false,
      platforms: undefined,
      data_sources: null,
      tags: "",
    });
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe("https://example.test/api/v1/detections");
    expect(parsed.searchParams.get("q")).toBe("tech:T1055 source:sigma");
    expect(parsed.searchParams.get("sources")).toBe("sigma,elastic");
    expect(parsed.searchParams.get("offset")).toBe("0");
    expect(parsed.searchParams.get("building_block")).toBe("false");
    for (const dropped of ["severities", "platforms", "data_sources", "tags"]) {
      expect(parsed.searchParams.has(dropped)).toBe(false);
    }
  });

  it("defaults to the public API", () => {
    expect(new DetectionExplorerClient().url("/health")).toBe("https://detectionexplorer.io/api/v1/health");
  });
});

describe("get", () => {
  it("sends a descriptive User-Agent and parses JSON", async () => {
    const { fetch, calls } = fakeFetch([json({ total: 1 })]);
    const client = new DetectionExplorerClient({ fetch });
    await expect(client.get("/detections/statistics")).resolves.toEqual({ total: 1 });
    const headers = calls[0].init?.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe(USER_AGENT);
    expect(USER_AGENT).toMatch(/^detection-explorer-mcp\/\d+\.\d+\.\d+ /);
    expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("waits out one 429 using Retry-After, then succeeds", async () => {
    const slept: number[] = [];
    const { fetch, calls } = fakeFetch([json({ detail: "slow down" }, 429, { "retry-after": "3" }), json({ ok: true })]);
    const client = new DetectionExplorerClient({ fetch, sleep: async (ms) => void slept.push(ms) });
    await expect(client.get("/x")).resolves.toEqual({ ok: true });
    expect(slept).toEqual([3000]);
    expect(calls).toHaveLength(2);
  });

  it("caps the Retry-After wait", async () => {
    const slept: number[] = [];
    const { fetch } = fakeFetch([json({}, 429, { "retry-after": "600" }), json({ ok: true })]);
    const client = new DetectionExplorerClient({ fetch, maxRetryAfterMs: 5000, sleep: async (ms) => void slept.push(ms) });
    await client.get("/x");
    expect(slept).toEqual([5000]);
  });

  it("surfaces a second 429 with the published limit", async () => {
    const { fetch } = fakeFetch([json({}, 429), json({}, 429)]);
    const client = new DetectionExplorerClient({ fetch, sleep: async () => {} });
    const error = await client.get("/x").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(429);
    expect(error.message).toContain("40 requests per 10 seconds");
  });

  it("reports FastAPI string and validation details", async () => {
    const { fetch } = fakeFetch([
      json({ detail: "Detection not found" }, 404),
      json({ detail: [{ loc: ["query", "limit"], msg: "Input should be less than or equal to 200" }] }, 422),
    ]);
    const client = new DetectionExplorerClient({ fetch });
    await expect(client.get("/detections/nope")).rejects.toThrow("GET /detections/nope -> HTTP 404: Detection not found");
    await expect(client.get("/detections")).rejects.toThrow("limit: Input should be less than or equal to 200");
  });

  it("falls back to the raw body for non-JSON errors", async () => {
    const { fetch } = fakeFetch([() => new Response("<html>Bad gateway</html>", { status: 502 })]);
    const client = new DetectionExplorerClient({ fetch });
    await expect(client.get("/x")).rejects.toThrow("HTTP 502: <html>Bad gateway</html>");
  });
});
