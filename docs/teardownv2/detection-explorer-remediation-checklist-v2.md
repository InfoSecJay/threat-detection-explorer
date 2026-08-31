# Detection Explorer — Remediation Checklist v2

Derived from the second review of detectionexplorer.io, 2026-08-31 (backend commit `2386de90`, corpus 15,584 rules).
Finding IDs (`R01`–`R25`) map back to the review. Sprint 0–5 items from v1 that are now done are listed at the bottom.

---

## Sprint A — One rewrite, three fixes (½ day)

- [ ] **A1 · Proxy `/api/*` on the apex domain.** `R01` `R02`
  Vercel rewrite `/api/:path*` → the Railway origin; change the frontend base URL to same-origin.
  *Done when:* `curl https://detectionexplorer.io/api/health` returns JSON, and `threat-detection-explorer-production.up.railway.app` appears nowhere in the JS bundle.

- [ ] **A2 · Verify the OG image renders.** `R01`
  `og:image` currently points at `/api/og/site.png` on the apex, which serves HTML. The generator itself works on the Railway host.
  *Done when:* the site URL and a rule URL both show an image in the LinkedIn Post Inspector and a Slack unfurl.

- [ ] **A3 · Fix RSS autodiscovery and the printed feed URLs.** `R01`
  `<link rel="alternate" href="/api/digest/feed.xml">` returns HTML today. The digest's Subscribe block prints raw `railway.app` URLs to users.
  *Done when:* a feed reader discovers the feeds from the page, and every printed feed URL is on `detectionexplorer.io`.

- [ ] **A4 · Add cache purge on sync completion.** `R02`
  The `s-maxage=900` headers start doing work once A1 lands; make sure a nightly ingest doesn't leave 15 minutes of stale counts.
  *Done when:* rule counts update within a minute of sync completion.

- [ ] **A5 · Add `Vary: User-Agent` to the HTML route.** `R03`
  Detail URLs are served from the CDN with `x-vercel-cache: HIT`, `age: 75310` and no `Vary`, so a UA-conditional prerender can't survive the cache.
  *Done when:* the header is present, or the cache key includes a bot flag.

- [ ] **A6 · Confirm the bot prerender actually fires.** `R03`
  Search Console → URL Inspection → Test Live URL on three detection detail pages; check the rendered HTML contains the `h1`.
  *Done when:* you've seen rendered content for a detail page in Search Console, not just from `/api/prerender/...`.

---

## Sprint B — Normalization: the canonical vocabulary (3–5 days)

> The methodology page now promises "one platform / data-source / event-type vocabulary." These items make that true.

- [ ] **B1 · Build a data-source alias table.** `R04`
  Collapse: `m365_*` vs `microsoft365_*`; `m365_defender` / `microsoft_defender_xdr` / `defender_endpoint` / `defender_cloud` / `windows_defender_event_log`; `azure_activity` / `azure_audit` / `azure_monitor_activity`; `windows_security_event_log` / `windows_event_logs`; `carbon_black` / `carbon_black_audit` / `carbon_black_alert`; `sentinelone` / `sentinelone_activity`.
  *Done when:* every accepted spelling maps to one canonical id, and the canonical list is published on `/methodology`.

- [ ] **B2 · Add a CI check for near-duplicate facet values.** `R04`
  Fail the build when a new facet value is a prefix-synonym or within a small edit distance of an existing one.
  *Done when:* a deliberate `microsoft365_test_audit` fixture fails the build.

- [ ] **B3 · Decide the generic-vs-product granularity rule.** `R04`
  `application_logs`, `webserver_logs`, `proxy_logs`, `network_traffic_logs`, `antivirus_logs`, `database_logs` currently sit at the same level as named product feeds.
  *Done when:* the rule is written down and applied consistently (either keep generics as a documented fallback tier, or resolve them).

- [ ] **B4 · Split `platform` into three fields.** `R05`
  `platform` (windows, linux, macos, container, cross_platform, unknown) · `surface` (endpoint, identity, cloud, saas, network, email) · `product` (vendor/app name). Panther and PyPanther alone contribute 50 of the current 56 platform values.
  *Done when:* `platform` has ≤10 values, and `crowdstrike` exists only as a product, never as a platform.

- [ ] **B5 · Give `event_type` a two-level hierarchy.** `R06`
  `event_category` → `event_subtype`, so `registry_event` rolls up `registry_set`/`add`/`delete`/`rename` and `file_event` rolls up its six children. Filtering a parent must include its children.
  *Done when:* no parent and child coexist as sibling facet values.

- [ ] **B6 · Normalize vendor event names out of `event_type`.** `R06`
  `file_delete_detected`, `file_block_shredding` (Elastic Defend); `ps_script`/`ps_module`/`ps_classic`, `sysmon_status`/`sysmon_error` (Sigma logsource names).
  *Done when:* no facet value is recognisably one vendor's internal string.

- [ ] **B7 · Add a `rule_modality` field.** `R06` `R07`
  Move `hunting_query`, `ml_detection`, `platform_alert`, `alert_correlation` out of `event_type` and `ml`, `threat_match`, `panther_correlation` out of `language`. Values: rule / hunting_query / ml_job / correlation / building_block.
  *Done when:* `language` contains only query languages and `event_type` only observed-event categories.

- [ ] **B8 · Fix the language-detection fallback.** `R07`
  `panther` appears as a language with count 1 — a single rule whose language wasn't detected, silently labelled with its source name.
  *Done when:* undetected languages are logged and counted, never defaulted to the source name.

---

## Sprint C — Normalization: honest field values (2–4 days)

- [ ] **C1 · Stop fabricating severity.** `R08`
  `elastic_protections` (1,314), `elastic_hunting` (140) and `okta` (34) return 100% "medium" because upstream publishes no severity. Add `severity: null` plus `severity_origin: upstream | derived | none`.
  *Done when:* the UI shows "not specified" and nulls are excluded from severity facet counts.

- [ ] **C2 · Recalibrate the Splunk severity mapping.** `R08`
  2,156 rules currently resolve to high:15, critical:0. Derive from `risk_score` with published thresholds.
  *Done when:* the distribution is defensible to a Splunk engineer, and the mapping table is on `/methodology`.

- [ ] **C3 · Read Elastic's `maturity` field into `status`.** `R09`
  All 2,084 Elastic rules currently return "stable".
  *Done when:* Elastic status reflects upstream maturity values.

- [ ] **C4 · Handle sources with no status concept.** `R09`
  Seven of thirteen sources return a constant. Sentinel returns "unknown" for 1,827 of 2,369 — 12% of the whole corpus.
  *Done when:* "not applicable" is distinguishable from "unknown", and the facet hides when the active source filter makes it meaningless.

- [ ] **C5 · Map Sublime's `attack_types` to ATT&CK.** `R10` — *highest value item on this list*
  All 1,209 Sublime rules currently have zero techniques and zero tactics. You already ingest `use_cases: Credential Phishing` from the same rules, so the upstream classification is being read and dropped. Suggested seed mapping: Credential Phishing → T1566.002 · attachment-based → T1566.001 · Malware/Ransomware → T1204.002 · BEC/Extortion → T1534.
  *Done when:* ≥1,100 Sublime rules carry techniques tagged `mapping_origin: derived`, and the site's technique-coverage figure is recomputed.

- [ ] **C6 · Do the same review for Google SecOps.** `R10`
  55 distinct techniques across 379 rules is low; check whether YARA-L metadata carries mappings that aren't being read.
  *Done when:* you've either raised the mapping rate or documented why it's genuinely that low.

- [ ] **C7 · Catch deprecated rules marked by title.** `R11`
  18 of 50 sampled hits carry "Deprecated" in the title, almost all Elastic ("Deprecated - Unusual Discovery Activity by User"). One surfaced at rank 3 for a plain "ransomware" search.
  *Done when:* a `deprecated` boolean exists, those rules are excluded from default views, coverage math and the digest, and the drift check alerts when a title gains a deprecation marker.

- [ ] **C8 · Namespace event IDs by channel.** `R12`
  438 values mixing bare Sysmon IDs (`1`, `3`, `7`, `10`) with Security channel IDs (`4104`, `4688`, `5145`). `eventid:1` is currently ambiguous.
  *Done when:* values are `sysmon:1` / `security:4688` / `powershell:4104`, with the bare number kept as a searchable alias.

- [ ] **C9 · Fix observable ranking skew.** `R13`
  `bash`/`sh`/`zsh`/`dash`/`ksh`/`fish`/`tcsh` occupy seven of the top fifteen process values because a few Elastic Protections rules enumerate every shell.
  *Done when:* the ranking counts distinct rule families, or enumerated sets collapse into one expandable row.

- [ ] **C10 · Publish an unclassified page with a burn-down.** `R14`
  Current: status 1,829 · platform 556 · data_source 280 · event_type 125 · severity 11.
  *Done when:* `/methodology/unclassified` exists, breaks down by source and field, and trends the count over time.

---

## Sprint D — Front end (2–3 days)

- [ ] **D1 · Slim the list endpoint.** `R15`
  149 KB for 25 rows; each row carries the full `detection_logic` (6.3 KB measured), `false_positives`, `references` and eight `extracted_*` arrays that the table never renders.
  *Done when:* the default list response is under 25 KB for 25 rows.

- [ ] **D2 · Bundle the daily-static reference calls.** `R16`
  `/api/mitre`, `/api/query/fields`, `/api/query/event-ids`, `/api/detections/filters`, `/api/detections/facets` refetch on every navigation.
  *Done when:* one `/api/bootstrap` call, cached client-side keyed on the corpus `updated_at` from `/api/health`.

- [ ] **D3 · Fix the font preloads.** `R17`
  Console warns both preloaded faces were "preloaded but not used" — the preload doesn't match the actual request. Six woff2 files load per page; Rajdhani ships as four static weights.
  *Done when:* no preload warnings, and Rajdhani is a single variable font.

- [ ] **D4 · Card layout for the detections list under 640px.** `R18`
  At 375px only the Title column is on screen; source, severity, platform, data source, event type and completeness are all off to the right. The checkbox column takes ~13% of the width.
  *Done when:* source and severity are visible without horizontal scrolling on a phone, and sort/limit share one row.

- [ ] **D5 · Finish the metric rename.** `R19`
  Table header says "Hygiene", detail page says "Metadata completeness", digest says "meta".
  *Done when:* one name in the table, detail page, digest, export header and API field.

- [ ] **D6 · Fix the score display contradiction.** `R20`
  "57/100" shown directly above "scored over the 58 points this format can express", with subscores summing to 33/58.
  *Done when:* the page shows "33 / 58 points" (or "57%"), not both denominators.

- [ ] **D7 · Fix the empty-query default sort.** `R21`
  "Relevance" with no query resolves to completeness score descending — the first five rows are all 88s and four of five are Splunk, the highest-scoring source.
  *Done when:* the default first page is source-diversified, or the label says what it actually does.

- [ ] **D8 · Fix source card truncation on the home page.** `R22`
  "Elastic Dete…", "Splunk Secur…", "Microsoft Se…", "Sublime Secu…", "Elastic Protec…" all clip at 1280px; 13 cards in a 5-column grid leaves a ragged final row.
  *Done when:* no source name is truncated at ≥1024px.

- [ ] **D9 · Canonicalize the address bar.** `R23`
  Legacy and vendor ids resolve correctly but stay in the URL, so people copy non-canonical links onward.
  *Done when:* `history.replaceState` swaps in the canonical id after the rule resolves.

- [ ] **D10 · Accessibility gaps.** `R24`
  Add a visually-hidden skip link (eight nav items precede content) and `<th scope="col">` on the data tables. Everything else checks out.
  *Done when:* both are in place.

- [ ] **D11 · Wire the version string to the build.** `R25`
  Header and footer read `v1.4.0` while `/api/health` reports commit `2386de90`.
  *Done when:* it moves with deploys, or it's removed.

- [ ] **D12 · Identify the two console 404s.** *(minor)*
  Present on every page load.
  *Done when:* the console is clean on load.

---

## Sprint E — Reach, still open from v1 (3–5 days)

- [ ] **E1 · Email subscription for the digest.** `R-carryover`
  Still RSS and JSON only. The week-archive work makes each issue permanently linkable, which makes email more valuable, not less.
  *Done when:* a visitor can subscribe from the digest page and receives the next issue.

- [ ] **E2 · Publish the API at `detectionexplorer.io/api/docs`.** `R-carryover`
  67 endpoints with a complete OpenAPI 3.1 spec, currently reachable only via the Railway hostname. Add a `/v1` prefix, a deprecation policy, rate limits and a fair-use note. Update `robots.txt`, which still has `Disallow: /api/`.
  *Done when:* the docs load on the apex and are linked from the footer.

- [ ] **E3 · Write three worked API examples.** `R-carryover`
  New rules → Slack; Navigator layer for an actor; diff your own rule set against the corpus.
  *Done when:* each runs unmodified against the live API.

- [ ] **E4 · Ship the MCP server.** `R-carryover`
  The read API is now fast enough (sub-110 ms) to sit behind an agent loop.
  *Done when:* published to npm and listed on the site.

- [ ] **E5 · Split the sitemap into an index.** *(minor)*
  17,300 URLs in one 2.5 MB file. Under the limits, but a per-section index lets Search Console report coverage by content type — which is how you'd notice detail pages failing to index.
  *Done when:* Search Console shows separate coverage for detections, mitre and actors.

- [ ] **E6 · Add `twitter:description` to the default shell.** *(minor)*
  Card, title and image are present; description is missing.

---

## Sprint F — Positioning (ongoing)

- [ ] **F1 · Lead with the gap, not the catalog.** `R-carryover`
  The home page still opens "15,584 detection rules from 13 open-source repositories"; "186 / 207 techniques covered" is the third stat in a row of four; the actor gap ranking is the fourth nav item.
  *Done when:* the first screen answers "what does nobody detect?" before "how many rules are there?"

- [ ] **F2 · Publish the corpus-health findings.** `R-new` — *strongest new content opportunity*
  From a 600-rule sample: 29% carry no ATT&CK mapping, 55% cite no references, 61% document no false positives. Nobody else can produce these numbers, your methodology page makes them defensible, and they're citable in a way "15,584 rules" is not.
  *Done when:* a dated report with a stable URL and downloadable data is live.

- [ ] **F3 · Spot-check search recall after the precision fix.** *(minor)*
  "ransomware" went from 588 hits to 274. Precision is much better; confirm you haven't lost rules whose logic matches without using the word.

- [ ] **F4 · Retain every nightly snapshot permanently.** `R-carryover`
  Still the only asset a competitor starting tomorrow cannot replicate.

- [ ] **F5 · Decide: portfolio piece or institution.** `R-carryover`
  Repo is still at zero stars — the distribution work hasn't started, and A1 is the thing standing between a good post and a good result.

---

## Closed since v1

Verified live, not taken on trust:

| v1 item | Evidence |
|---|---|
| S0.1–S0.3 admin routes | Sync / ingest / mitre-refresh / scheduler-trigger absent from the public OpenAPI spec |
| S0.4–S0.5 license, repo metadata | Apache-2.0 declared on `/methodology`; site renamed Detection Explorer |
| S1.4–S1.6 sitemap | 17,300 URLs, real XML, `lastmod`, `max-age=3600` |
| S1.7 mobile nav | Hamburger below 768px |
| S1.9 analytics | Requests present (blocked in my test browser) |
| S2.2, S2.4, S2.5 perf | Facets 1,503 → 95 ms; list 1,278 → 102 ms; `s-maxage` headers set |
| S2.9 self-hosted fonts | Served from `/fonts/`, no third-party font host |
| S3.1–S3.2 scoring | Renamed, format-aware denominators, caveat above the number, no vendor ranking; per-source means 34–70 → 54–74 |
| S3.3–S3.5 permalinks | Legacy id, vendor id and canonical id all resolve to one rule; guarantee published |
| S3.7 cross-vendor panel | Now reports "COVERAGE GAP — no other tracked source…" instead of padding with same-source rules |
| S3.8 search relevance | Six broad queries all return an on-topic rule at rank 1 |
| S3.9 licenses | Per-source column on `/methodology`, license badge on rule pages |
| S4.1–S4.2 methodology | Promoted to `/methodology`, in the nav, with counting, taxonomy, permalink and licensing sections |
| S4.4 digest archive | `/digest/2026-w35` with prev/next and an explicit permanence note |
| S4.11 contribution path | "Suggest a source" link in the footer |
| S4.13 default sort | Changed from Created (Newest) — though see `R21` |
| S4.15 author fallback | "Sublime (upstream repo)" instead of "unknown" |

**Still open from v1:** email digest (E1), public API front door (E2–E3), MCP server (E4), lead-with-the-gap (F1), snapshot retention (F4), portfolio-vs-institution (F5).

---

## Rollup

| Sprint | Items | Theme | Priority |
|---|---|---|---|
| A | 6 | One rewrite fixes OG, RSS, caching, docs | Do first — blocks sharing |
| B | 8 | Canonical taxonomy: platform, data source, event type | Highest normalization value |
| C | 10 | Honest field values: severity, status, ATT&CK, deprecated | C5 is the single best item |
| D | 12 | Payload, mobile, naming, a11y | User-facing polish |
| E | 6 | API front door, email, MCP | Growth |
| F | 5 | Positioning and durability | Ongoing |

**Suggested labels:** `infra`, `normalization`, `taxonomy`, `frontend`, `a11y`, `api`, `growth`
**Suggested milestones:** `v1.5 — unblocked`, `v1.6 — canonical`, `v2.0 — reference`
