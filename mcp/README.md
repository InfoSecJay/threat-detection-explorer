# Detection Explorer MCP server

An [MCP](https://modelcontextprotocol.io) server for
[Detection Explorer](https://detectionexplorer.io): search, compare and map
15,000+ open-source detection rules from 13 repositories (SigmaHQ, Elastic
detection rules, hunting queries and protections, Splunk Security Content,
Microsoft Sentinel, Panther, PyPanther, Sublime, Google SecOps, Okta, Auth0,
LOLRMM), normalized into one schema, mapped to MITRE ATT&CK, with the
observables each rule keys on.

It wraps the public, read-only
[Detection Explorer API](https://detectionexplorer.io/api/docs). No account
or API key is needed.

## Install

Requires Node.js 20 or newer.

**Claude Code**

```bash
claude mcp add detection-explorer -- npx -y detection-explorer-mcp
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`~/.cursor/mcp.json`)
and other clients that use the `mcpServers` format:

```json
{
  "mcpServers": {
    "detection-explorer": {
      "command": "npx",
      "args": ["-y", "detection-explorer-mcp"]
    }
  }
}
```

On Windows, if the client cannot find `npx`, use
`"command": "cmd"` with `"args": ["/c", "npx", "-y", "detection-explorer-mcp"]`.

**VS Code** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "detection-explorer": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "detection-explorer-mcp"]
    }
  }
}
```

## Things to ask

- Which Sigma rules for T1055 have no same-behaviour Elastic rule?
- Scoped to Elastic and Sigma, which APT29 techniques have no public rule?
- Compare these two rules: what does each key on, and what does each exclude?
- Which rules key on `rundll32.exe`, and what do they usually pair it with?
- What changed upstream in the last 7 days?
- Give me an ATT&CK Navigator layer for Scattered Spider.

## Tools

| Tool | What it answers |
| --- | --- |
| `search_detections` | Search with the site's query language (`tech:T1055 source:sigma`, `actor:APT29 AND sev:high`) plus filters; `no_equivalent_in` finds porting gaps. Rows of a `content:` query carry `content_match` (where the term hit; `exclusion_only` when it sits inside an allowlist, so the rule does not detect it). |
| `get_detection` | One rule in full: logic, ATT&CK mapping, data sources, false positives, deploy prerequisites, extracted observables, pinned upstream link, and `same_rule` for a Panther/PyPanther twin. |
| `find_related_detections` | Same-behaviour rules in other repositories, gated on shared observables, with the reasons. |
| `compare_detections` | Observable-level diff of 2 to 6 rules: shared, unique and excluded observables. |
| `technique_coverage` | Rule counts per repository for one technique, the observables each vendor keys on, groups and software that use it. |
| `actor_coverage` | An ATT&CK group or software by name, alias or ID: covered techniques, gaps, per-source coverage; scope it to your repositories with `sources`. |
| `actor_navigator_layer` | ATT&CK Navigator layer JSON scored by public rule coverage. |
| `coverage_gap` | Techniques one repository covers and another does not. |
| `observable_lookup` | Every rule that keys on a process, event ID, path, registry key, network indicator, API action or table. |
| `whats_new` | New, modified and removed rules over the last N days. |
| `corpus_overview` | Rule counts and the last sync of each upstream repository. |
| `query_language` | The fields `search_detections` understands, with examples. |

Coverage numbers describe public rules, not any organisation's deployed
detections. The methodology behind every count is at
[detectionexplorer.io/methodology](https://detectionexplorer.io/methodology).

## Limits and data

- The public API allows 40 requests per 10 seconds per IP. The server waits
  out one `429` using `Retry-After`, then reports the limit to the model.
- The corpus is synced nightly from each upstream repository.
- Rules keep their upstream licenses (DRL, Elastic License 2.0, Apache-2.0
  and others). Check the upstream link before redistributing rule content.
- The server sends only tool arguments to `detectionexplorer.io`. It collects
  no telemetry; its User-Agent names the package version.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DETECTION_EXPLORER_API_URL` | `https://detectionexplorer.io/api/v1` | Point at another deployment, e.g. a local backend at `http://127.0.0.1:8000/api/v1`. |

## Development

```bash
cd mcp
npm install
npm run build
npm test          # unit tests, no network
npm run smoke     # starts the built server over stdio and calls every tool against the live API
```

Source and issues: [InfoSecJay/threat-detection-explorer](https://github.com/InfoSecJay/threat-detection-explorer)
(this package lives in `mcp/`).

## License

Apache-2.0. Detection rules served through the API remain under their
upstream repositories' licenses.
