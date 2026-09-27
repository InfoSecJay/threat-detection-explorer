/** Content for the /mcp page (#92 S4.10), kept out of the component file
 * so fast refresh works. TOOLS and WORKFLOWS are checked against the MCP
 * server's registerTool calls by mcp/test/site-copies.test.ts. */

export const MCP_PACKAGE = 'detection-explorer-mcp';
export const NPM_URL = `https://www.npmjs.com/package/${MCP_PACKAGE}`;
export const SOURCE_URL = 'https://github.com/InfoSecJay/threat-detection-explorer/tree/master/mcp';

const MCP_SERVERS_JSON = JSON.stringify(
  { mcpServers: { 'detection-explorer': { command: 'npx', args: ['-y', MCP_PACKAGE] } } },
  null,
  2,
);

export const CLIENTS: Array<{ name: string; where: string; code: string; note?: string }> = [
  {
    name: 'Claude Code',
    where: 'run once in a terminal',
    code: `claude mcp add detection-explorer -- npx -y ${MCP_PACKAGE}`,
  },
  {
    name: 'Claude Desktop',
    where: 'Settings > Developer > Edit Config (claude_desktop_config.json)',
    code: MCP_SERVERS_JSON,
    note: 'On Windows, if npx is not found, use "command": "cmd" with "args": ["/c", "npx", "-y", "detection-explorer-mcp"].',
  },
  {
    name: 'Cursor',
    where: '~/.cursor/mcp.json',
    code: MCP_SERVERS_JSON,
  },
  {
    name: 'VS Code',
    where: '.vscode/mcp.json in your workspace',
    code: JSON.stringify(
      { servers: { 'detection-explorer': { type: 'stdio', command: 'npx', args: ['-y', MCP_PACKAGE] } } },
      null,
      2,
    ),
  },
];

export const WORKFLOWS: Array<{ title: string; prompt: string; tools: string[]; why: string }> = [
  {
    title: 'Find porting gaps between vendors',
    prompt: 'Which Sigma rules for T1055 have no same-behaviour Elastic rule? Group them by what they key on.',
    tools: ['search_detections', 'find_related_detections'],
    why: 'Equivalence needs a shared observable, not just a shared ATT&CK tag, so "no Elastic equivalent" means no Elastic rule watches the same process, event or API call.',
  },
  {
    title: 'Score an actor against your stack',
    prompt: 'We run Elastic and Sigma. Which APT29 techniques have no public rule in those repositories?',
    tools: ['actor_coverage'],
    why: 'Coverage is scored against the repositories you name. Hunting queries, passthrough alerts and indicator lists do not count as coverage unless you ask.',
  },
  {
    title: 'Diff rules observable by observable',
    prompt: 'Compare these two rules. What does each key on, what does only one of them see, and what does each exclude?',
    tools: ['compare_detections'],
    why: 'Process names, event IDs, paths, registry keys, fields and API actions are extracted from each rule\'s logic, exclusions included.',
  },
  {
    title: 'Pivot on an observable',
    prompt: 'Which rules key on rundll32.exe? What do they usually pair it with, and how many exclude it instead?',
    tools: ['observable_lookup'],
    why: 'Answers across every repository at once, split by source, technique and platform, with the vendor field names each rule uses.',
  },
  {
    title: 'Triage a new CVE',
    prompt: 'Is there a public detection for CVE-2025-5777? Which SIEM is it written for, and what data does it need?',
    tools: ['search_detections', 'get_detection'],
    why: 'Rule records carry data sources, deploy prerequisites and false-positive notes, so the answer covers what it takes to run the rule.',
  },
  {
    title: 'Keep up with upstream',
    prompt: 'What changed in the public rule repositories this week? Summarise the new rules by technique.',
    tools: ['whats_new'],
    why: 'All thirteen repositories sync nightly, and every rule is pinned to the upstream commit it came from.',
  },
  {
    title: 'Export a Navigator layer',
    prompt: 'Build an ATT&CK Navigator layer for Scattered Spider and list the techniques with no public rule.',
    tools: ['actor_navigator_layer', 'actor_coverage'],
    why: 'Layers are scored by public rule coverage and open directly in the ATT&CK Navigator.',
  },
];

export const TOOLS: Array<{ name: string; does: string }> = [
  { name: 'search_detections', does: 'Search with the site query language plus filters; no_equivalent_in finds rules another vendor lacks.' },
  { name: 'get_detection', does: 'One rule in full: logic, ATT&CK mapping, data sources, false positives, deploy prerequisites, pinned upstream link.' },
  { name: 'find_related_detections', does: 'Same-behaviour rules in other repositories, with the shared observables that matched.' },
  { name: 'compare_detections', does: 'Observable-level diff of 2 to 6 rules: shared, unique and excluded observables.' },
  { name: 'technique_coverage', does: 'Rule counts per repository for one technique and the observables each vendor keys on.' },
  { name: 'actor_coverage', does: 'A group or software by name, alias or ID: covered techniques and gaps, scoped to your repositories.' },
  { name: 'actor_navigator_layer', does: 'ATT&CK Navigator layer JSON scored by public rule coverage.' },
  { name: 'coverage_gap', does: 'Techniques one repository covers and another does not.' },
  { name: 'observable_lookup', does: 'Every rule keyed on a process, event ID, path, registry key, network indicator, API action or table.' },
  { name: 'whats_new', does: 'New, modified and removed rules over the last N days.' },
  { name: 'corpus_overview', does: 'Rule counts and the last sync of each upstream repository.' },
  { name: 'query_language', does: 'Every field search_detections understands, with examples.' },
];

export const DIFFERENCES: Array<{ title: string; body: string }> = [
  {
    title: 'Thirteen repositories, one schema',
    body: 'SigmaHQ, Elastic rules, hunting queries and protections, Splunk, Microsoft Sentinel, Panther, PyPanther, Sublime, Google SecOps, Okta, Auth0 and LOLRMM, normalized to the same platforms, data sources and event types.',
  },
  {
    title: 'Observables, not just tags',
    body: 'Each rule is parsed for what it actually watches. Same-behaviour matches and diffs work on those observables, so they survive vendors tagging the same logic differently.',
  },
  {
    title: 'Your stack, not the whole corpus',
    body: 'Actor coverage and gaps can be scored against only the repositories you deploy, which is the number that matters in a coverage review.',
  },
  {
    title: 'Answers you can check',
    body: 'Every rule the assistant cites comes with its page here, where the pinned upstream commit, license and change history sit next to the logic.',
  },
  {
    title: 'No account, no key',
    body: 'The server calls the same public, read-only API documented at /api/docs. Nothing to sign up for and no telemetry.',
  },
];
