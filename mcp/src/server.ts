// Tool definitions. Every tool is a read-only GET against the public API;
// descriptions are written for the model choosing between them.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { ApiError, DetectionExplorerClient } from "./client.js";
import {
  actorSummary,
  corpusOverview,
  detectionDetail,
  diffSummary,
  digestSummary,
  observableSummary,
  queryLanguage,
  relatedSummary,
  searchResult,
  techniqueSummary,
} from "./format.js";
import { VERSION } from "./version.js";

export const SOURCES = [
  "sigma",
  "elastic",
  "elastic_hunting",
  "elastic_protections",
  "splunk",
  "sentinel",
  "sublime",
  "google_secops",
  "panther",
  "pypanther",
  "okta",
  "auth0",
  "lolrmm",
] as const;

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;

const OBSERVABLE_KINDS = ["process", "eventid", "path", "registry", "network", "action", "table", "resource"] as const;

/** Friendly sort names -> API sort_by / sort_order. */
export const SORTS = {
  relevance: ["relevance", "desc"],
  newest: ["rule_created_date", "desc"],
  recently_modified: ["rule_modified_date", "desc"],
  quality: ["quality_score", "desc"],
  title: ["title", "asc"],
} as const;

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/i;
const ATTACK_OBJECT_ID = /^[GS]\d{4}$/i;

const READ_ONLY = { readOnlyHint: true, idempotentHint: true, openWorldHint: true } as const;

const sourceList = z.array(z.enum(SOURCES));

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

function ok(value: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function fail(error: unknown): ToolResult {
  const message = error instanceof ApiError || error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text", text: message }], isError: true };
}

async function run(fn: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (error) {
    return fail(error);
  }
}

/** "APT29", "Cozy Bear", "G0016" or "S0154" -> an ATT&CK ID, plus what else matched. */
export async function resolveActor(client: DetectionExplorerClient, actor: string) {
  const trimmed = actor.trim();
  if (ATTACK_OBJECT_ID.test(trimmed)) return { id: trimmed.toUpperCase(), alternatives: [] as string[] };
  const found = await client.get<{ items?: Array<{ id: string; name: string }> }>("/actors", { q: trimmed, per_page: 5 });
  const items = found.items ?? [];
  if (!items.length) {
    throw new Error(`No ATT&CK group or software matches "${trimmed}". Try the ATT&CK ID (G0016, S0154) or another alias.`);
  }
  return { id: items[0].id, alternatives: items.slice(1).map((i) => `${i.id} ${i.name}`) };
}

export function createServer(client: DetectionExplorerClient): McpServer {
  const server = new McpServer(
    { name: "detection-explorer", version: VERSION },
    {
      instructions:
        "Detection Explorer indexes 15,000+ open-source detection rules from 13 repositories (Sigma, Elastic, Splunk, Microsoft Sentinel, Panther, Sublime, Google SecOps, Okta, Auth0, LOLRMM) in one schema, mapped to MITRE ATT&CK, with the observables each rule keys on. " +
        "Start with search_detections (call query_language for the field list), open rules with get_detection, and use find_related_detections / compare_detections to port or dedupe across vendors. " +
        "Coverage tools (technique_coverage, actor_coverage, coverage_gap) describe public rules, not any organisation's deployed detections. " +
        "The API is rate limited to 40 requests per 10 seconds; prefer one broad query over many narrow ones. Always give the user the detectionexplorer.io url of rules you cite.",
    },
  );

  server.registerTool(
    "search_detections",
    {
      title: "Search detection rules",
      description:
        "Search the rule corpus. `query` uses the site's Lucene-style language, e.g. `tech:T1055 source:sigma`, `actor:APT29 AND sev:high`, `process:rundll32.exe NOT platform:linux`, `title:\"cobalt strike\"`, or a bare CVE ID such as `CVE-2025-5777`. " +
        "Filters combine with the query. Use no_equivalent_in to find porting gaps (Sigma rules with no same-behaviour Elastic rule: sources=[sigma], no_equivalent_in=[elastic]). Returns slim rows; open one with get_detection.",
      inputSchema: {
        query: z.string().optional().describe("Query-language expression; see query_language for fields"),
        sources: sourceList.optional().describe("Only these repositories"),
        severities: z.array(z.enum(SEVERITIES)).optional(),
        techniques: z.array(z.string().regex(TECHNIQUE_ID)).optional().describe("ATT&CK technique IDs, e.g. T1059.001"),
        platforms: z.array(z.string()).optional().describe("windows, linux, macos, container, cross_platform"),
        data_sources: z.array(z.string()).optional().describe("Canonical data sources, e.g. sysmon, aws_cloudtrail, okta_system_log"),
        has_equivalent_in: sourceList.optional().describe("Rules that have a same-behaviour rule in any of these sources"),
        no_equivalent_in: sourceList.optional().describe("Rules with no same-behaviour rule in any of these sources"),
        sort: z.enum(Object.keys(SORTS) as [keyof typeof SORTS, ...Array<keyof typeof SORTS>]).optional()
          .describe("relevance (default when query is set), newest (default otherwise), recently_modified, quality, title"),
        limit: z.number().int().min(1).max(50).default(20),
        offset: z.number().int().min(0).default(0),
      },
      annotations: { title: "Search detection rules", ...READ_ONLY },
    },
    async (args) =>
      run(async () => {
        const sort = args.sort ?? (args.query ? "relevance" : "newest");
        const [sortBy, sortOrder] = SORTS[sort];
        const page = await client.get("/detections", {
          q: args.query,
          sources: args.sources,
          severities: args.severities,
          mitre_techniques: args.techniques?.map((t) => t.toUpperCase()),
          platforms: args.platforms,
          data_sources: args.data_sources,
          equivalent_in: args.has_equivalent_in,
          no_equivalent_in: args.no_equivalent_in,
          sort_by: sortBy,
          sort_order: sortOrder,
          limit: args.limit,
          offset: args.offset,
        });
        return searchResult(page, args.offset);
      }),
  );

  server.registerTool(
    "get_detection",
    {
      title: "Get one detection rule",
      description:
        "Full record for one rule by its Detection Explorer id (from search results): description, detection logic, ATT&CK mapping, data sources, false positives, references, deploy prerequisites, extracted observables and pinned upstream links. Set include_raw for the original rule file.",
      inputSchema: {
        id: z.string().min(1).describe("Detection Explorer rule id (UUID from search results)"),
        include_raw: z.boolean().default(false).describe("Include the upstream rule file verbatim (can be long)"),
      },
      annotations: { title: "Get one detection rule", ...READ_ONLY },
    },
    async ({ id, include_raw }) =>
      run(async () => detectionDetail(await client.get(`/detections/${encodeURIComponent(id)}`), include_raw)),
  );

  server.registerTool(
    "find_related_detections",
    {
      title: "Find same-behaviour rules",
      description:
        "Rules that detect the same behaviour as a given rule, in other vendors' repositories and in its own. Matches are gated on shared observables (process names, event IDs, paths, API actions), with the reasons listed; technique-only overlaps are reported separately. Use it to port a rule or check for duplicates.",
      inputSchema: {
        id: z.string().min(1).describe("Detection Explorer rule id"),
        limit: z.number().int().min(1).max(25).default(10),
      },
      annotations: { title: "Find same-behaviour rules", ...READ_ONLY },
    },
    async ({ id, limit }) =>
      run(async () => relatedSummary(await client.get(`/detections/${encodeURIComponent(id)}/related`, { limit }))),
  );

  server.registerTool(
    "compare_detections",
    {
      title: "Diff rules observable by observable",
      description:
        "Observable-level diff of 2 to 6 rules: which process names, event IDs, paths, registry keys, fields and API actions every rule keys on, what each has alone, and what each explicitly excludes. Also diffs techniques, data sources and platforms.",
      inputSchema: {
        ids: z.array(z.string().min(1)).min(2).max(6).describe("Detection Explorer rule ids"),
      },
      annotations: { title: "Diff rules observable by observable", ...READ_ONLY },
    },
    async ({ ids }) => run(async () => diffSummary(await client.get("/compare/diff", { ids }))),
  );

  server.registerTool(
    "technique_coverage",
    {
      title: "ATT&CK technique coverage",
      description:
        "How the public corpus covers one ATT&CK technique: rule counts per repository and severity, the observables each vendor keys on, recent momentum, and the groups and software known to use it.",
      inputSchema: {
        technique_id: z.string().regex(TECHNIQUE_ID).describe("e.g. T1055 or T1059.001"),
      },
      annotations: { title: "ATT&CK technique coverage", ...READ_ONLY },
    },
    async ({ technique_id }) =>
      run(async () => techniqueSummary(await client.get(`/mitre/techniques/${technique_id.toUpperCase()}/profile`))),
  );

  server.registerTool(
    "actor_coverage",
    {
      title: "Threat actor coverage",
      description:
        "Coverage of an ATT&CK group or software (name, alias or ID: \"APT29\", \"Cozy Bear\", \"G0016\", \"S0154\"): which of its techniques have public rules and which are gaps, per-source coverage, and rules that name the actor. Scope to the repositories an organisation actually runs with `sources`.",
      inputSchema: {
        actor: z.string().min(1).describe("Group or software name, alias, or ATT&CK ID"),
        sources: sourceList.optional().describe("Score coverage against only these repositories"),
        match_mode: z.enum(["exact", "coverage", "mention"]).default("exact")
          .describe("exact: rules tagged with or named after the actor; coverage: any rule for its techniques; mention: the name appears in the rule"),
        include_all_rule_types: z.boolean().default(false)
          .describe("Count hunting, building-block, passthrough and indicator-only rules as coverage (off by default)"),
      },
      annotations: { title: "Threat actor coverage", ...READ_ONLY },
    },
    async ({ actor, sources, match_mode, include_all_rule_types }) =>
      run(async () => {
        const { id, alternatives } = await resolveActor(client, actor);
        const detail = await client.get(`/actors/${id}`, {
          sources,
          match_mode,
          coverage: include_all_rule_types ? "all" : "strict",
        });
        // `sources` scopes technique coverage AND the Named / Mentions
        // rule list server-side (#170), so the answer is passed through.
        const summary = {
          ...actorSummary(detail),
          ...(alternatives.length ? { other_matches_for_query: alternatives } : {}),
        };
        return summary;
      }),
  );

  server.registerTool(
    "actor_navigator_layer",
    {
      title: "ATT&CK Navigator layer for an actor",
      description:
        "ATT&CK Navigator layer JSON for a group or software, scored by public rule coverage. Save the text as a .json file and open it in the Navigator.",
      inputSchema: {
        actor: z.string().min(1).describe("Group or software name, alias, or ATT&CK ID"),
        match_mode: z.enum(["exact", "coverage", "mention"]).default("coverage"),
      },
      annotations: { title: "ATT&CK Navigator layer for an actor", ...READ_ONLY },
    },
    async ({ actor, match_mode }) =>
      run(async () => {
        const { id } = await resolveActor(client, actor);
        const path = id.startsWith("S") ? `/software/${id}/navigator-layer` : `/actors/${id}/navigator-layer`;
        return client.get(path, { match_mode });
      }),
  );

  server.registerTool(
    "coverage_gap",
    {
      title: "Technique gap between two repositories",
      description:
        "ATT&CK techniques that base_source has rules for and compare_source does not, plus the overlap and what only compare_source covers. Technique level only; for rule-level porting gaps use search_detections with no_equivalent_in.",
      inputSchema: {
        base_source: z.enum(SOURCES),
        compare_source: z.enum(SOURCES),
      },
      annotations: { title: "Technique gap between two repositories", ...READ_ONLY },
    },
    async ({ base_source, compare_source }) =>
      run(async () => client.get("/compare/coverage-gap", { base_source, compare_source })),
  );

  server.registerTool(
    "observable_lookup",
    {
      title: "Rules that key on an observable",
      description:
        "Every rule that keys on one observable, e.g. process rundll32.exe, eventid 4688, registry Run key, API action CreateAccessKey: counts by source, technique and platform, the fields used, what co-occurs with it, how many rules exclude it, and the rules themselves.",
      inputSchema: {
        kind: z.enum(OBSERVABLE_KINDS).describe("process, eventid, path, registry, network, action (cloud/identity API action), table, resource"),
        value: z.string().min(1).describe("e.g. rundll32.exe, 4688, CreateAccessKey"),
      },
      annotations: { title: "Rules that key on an observable", ...READ_ONLY },
    },
    async ({ kind, value }) =>
      run(async () =>
        observableSummary(await client.get(`/observables/${kind}/${encodeURIComponent(value)}`)),
      ),
  );

  server.registerTool(
    "whats_new",
    {
      title: "New and updated rules",
      description:
        "What changed upstream in the last N days: new, modified and removed rules per repository, the techniques they cluster on, and coverage momentum.",
      inputSchema: {
        days: z.number().int().min(1).max(90).default(7),
      },
      annotations: { title: "New and updated rules", ...READ_ONLY },
    },
    async ({ days }) => run(async () => digestSummary(await client.get("/digest", { days, limit: 15, rules_limit: 100 }))),
  );

  server.registerTool(
    "corpus_overview",
    {
      title: "Corpus overview",
      description: "Rule counts per repository, severity and rule type, and when each upstream repository was last synced.",
      inputSchema: {},
      annotations: { title: "Corpus overview", ...READ_ONLY },
    },
    async () =>
      run(async () => {
        const [stats, repos] = await Promise.all([client.get("/detections/statistics"), client.get<unknown[]>("/repositories")]);
        return corpusOverview(stats, Array.isArray(repos) ? repos : []);
      }),
  );

  server.registerTool(
    "query_language",
    {
      title: "Query language reference",
      description: "Every field the search_detections query language understands, with aliases and examples.",
      inputSchema: {},
      annotations: { title: "Query language reference", ...READ_ONLY },
    },
    async () => run(async () => queryLanguage(await client.get("/query/fields"))),
  );

  return server;
}
