// The site keeps two copies of this server's tool list: the /mcp page
// (frontend/src/pages/mcp/content.ts) and its bot-facing prerender
// (backend/app/api/routes/prerender.py, MCP_TOOLS). Both must name
// exactly the tools server.ts registers. Skipped when the package is
// checked out without the rest of the repository.

import { existsSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf-8");
const repoFile = (rel: string) => new URL(`../../${rel}`, import.meta.url);

const registered = [...read("../src/server.ts").matchAll(/registerTool\(\s*"([a-z_]+)"/g)].map((m) => m[1]).sort();

const page = repoFile("frontend/src/pages/mcp/content.ts");
const prerender = repoFile("backend/app/api/routes/prerender.py");

describe.skipIf(!existsSync(page) || !existsSync(prerender))("site copies of the tool list", () => {
  it("server.ts registers the twelve documented tools", () => {
    expect(registered).toHaveLength(12);
  });

  it("the /mcp page table lists exactly those tools", () => {
    const source = readFileSync(page, "utf-8");
    const table = source.slice(source.indexOf("export const TOOLS"), source.indexOf("export const DIFFERENCES"));
    const names = [...table.matchAll(/name: '([a-z_]+)'/g)].map((m) => m[1]).sort();
    expect(names).toEqual(registered);
  });

  it("the /mcp page workflows cite only registered tools", () => {
    const source = readFileSync(page, "utf-8");
    const block = source.slice(source.indexOf("export const WORKFLOWS"), source.indexOf("export const TOOLS"));
    const cited = new Set([...block.matchAll(/tools: \[([^\]]*)\]/g)].flatMap((m) => [...m[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1])));
    expect(cited.size).toBeGreaterThan(5);
    for (const tool of cited) expect(registered).toContain(tool);
  });

  it("the prerendered /mcp page lists exactly those tools", () => {
    const source = readFileSync(prerender, "utf-8");
    const block = source.slice(source.indexOf("MCP_TOOLS = ("), source.indexOf("@router.get(\"/mcp\""));
    const names = [...block.matchAll(/\("([a-z_]+)", "/g)].map((m) => m[1]).sort();
    expect(names).toEqual(registered);
  });
});
