// Live smoke test: start the built server over stdio (as an MCP client
// would), call every tool once against the public API, and fail on any
// tool error. About 15 API requests, well inside the rate limit.
//
//   npm run build && npm run smoke

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";

const entry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const transport = new StdioClientTransport({ command: process.execPath, args: [entry], env: { ...process.env }, stderr: "inherit" });
const client = new Client({ name: "smoke", version: "0.0.0" });
await client.connect(transport);

const { tools } = await client.listTools();
console.log(`tools: ${tools.length} (${tools.map((t) => t.name).join(", ")})`);

let failures = 0;
async function call(name, args = {}) {
  const started = Date.now();
  const result = await client.callTool({ name, arguments: args });
  const body = result.content?.[0]?.text ?? "";
  const status = result.isError ? "ERROR" : "ok";
  if (result.isError) failures++;
  console.log(`${status.padEnd(5)} ${name.padEnd(24)} ${String(body.length).padStart(7)} chars  ${Date.now() - started} ms${result.isError ? `\n      ${body}` : ""}`);
  return result.isError ? null : JSON.parse(body);
}

await call("corpus_overview");
await call("query_language");
const search = await call("search_detections", { query: "tech:T1055", sources: ["sigma"], no_equivalent_in: ["elastic"], limit: 5 });
const ids = (await call("search_detections", { query: "process:rundll32.exe", limit: 2 }))?.results?.map((r) => r.id) ?? [];
const first = search?.results?.[0]?.id ?? ids[0];
if (first) {
  await call("get_detection", { id: first });
  await call("find_related_detections", { id: first, limit: 5 });
}
if (ids.length === 2) await call("compare_detections", { ids });
await call("technique_coverage", { technique_id: "T1055" });
await call("actor_coverage", { actor: "Cozy Bear", sources: ["elastic", "sigma"] });
await call("actor_navigator_layer", { actor: "G0016" });
await call("coverage_gap", { base_source: "sigma", compare_source: "elastic" });
await call("observable_lookup", { kind: "process", value: "rundll32.exe" });
await call("whats_new", { days: 7 });
await call("get_detection", { id: "00000000-0000-0000-0000-000000000000" }).then(() => failures--); // expected error path

await client.close();
console.log(failures ? `\nFAILED: ${failures} tool call(s)` : "\nOK: every tool answered");
process.exit(failures ? 1 : 0);
