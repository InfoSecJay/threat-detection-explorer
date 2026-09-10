# Detection Explorer panel review

> Two-person product review · build 7f51b8a · corpus synced 2026-09-10

Target detectionexplorer.io · Corpus 15,662 rules · 13 repos · Reviewed 2026-09-10 · Findings 3 P0 · 5 P1 · 13 P2 · 1 P3 bundle

- **A · DESIGN** — Principal product designer. Judges IA, interaction cost, state handling, accessibility, performance.
- **B · DETECTION** — Staff detection engineer. Judges whether it survives triage, coverage assessment, gap analysis and porting.

## Fix tracker

Tick items off as fixes ship. IDs match the findings below and the backlog ranking.

- [ ] **DX-01** `P0` Actor pages headline a “weighted coverage” percentage the data can't support — _Effort S / M_
- [ ] **DX-02** `P0` “Same behaviour, other vendors” is ATT&CK tag overlap, not behaviour — _Effort S_
- [ ] **DX-03** `P0` The Navigator layer export paints covered techniques in the “gap” colour — _Effort S_
- [ ] **DX-04** `P1` Actor lookup returns silent zeros and disagrees with the actor page — _Effort S–M_
- [ ] **DX-05** `P1` Alert passthroughs, hash lists and upstream mis-tags count as technique coverage — _Effort M_
- [ ] **DX-06** `P1` Splunk rules inherit every OS their data sources support — _Effort M_
- [ ] **DX-07** `P1` T2 — “Sigma for T1055 we don't have in Elastic” — has no path — _Effort M–L_
- [ ] **DX-08** `P1` The three match modes are named three different ways — _Effort S_
- [ ] **DX-09** `P2` Every rule date renders one day early west of UTC — _Effort S_
- [ ] **DX-10** `P2` The headline count includes what the methodology says it excludes — _Effort S (copy) / M (dedup)_
- [ ] **DX-11** `P2` One technique, three rule counts — _Effort S_
- [ ] **DX-12** `P2` Bare-word search hits rule bodies, including exclusion lists — _Effort S_
- [ ] **DX-13** `P2` A security site without security headers, running a floating CDN script on its origin — _Effort S_
- [ ] **DX-14** `P2` Intel “trending” is one repo's bulk rewrite — _Effort M_
- [ ] **DX-15** `P2` Upstream links point at moving branches, and the branches disagree with the methodology — _Effort S_
- [ ] **DX-16** `P2` Normalization drops the deploy prerequisites — _Effort S–M_
- [ ] **DX-17** `P2` The rule table omits the two columns DEs triage on — _Effort S_
- [ ] **DX-18** `P2` Crawl hygiene: soft 404s, a frozen lastmod, UA-gated rendering — _Effort M_
- [ ] **DX-19** `P2` Removed or unknown rules show a raw client error — _Effort M (tombstones) / S (copy)_
- [ ] **DX-20** `P2` Small secondary text fails AA contrast on the dark theme — _Effort S_
- [ ] **DX-21** `P2` At 390 px the search box is 53 px wide and the actor page scrolls sideways — _Effort S_
- [ ] **DX-22** `P3` Polish bundle — _Effort S each_

## 1 · Verdict

Would each reviewer bookmark it and use it in a real workweek?

### A · DESIGN: Yes — bookmarked.

The query bar and the facets are one model serialized into `?q=`, and the rule page holds provenance, license, history and logic without a second click. That beats most peer tools. What stops it scoring higher is fixable: numbers that disagree between surfaces, and small-text contrast.

### B · DETECTION: Yes for lookup. No for coverage.

I'd use it weekly to vet a rule (T4) and read the Digest. I wouldn't let it near a leadership slide: `/actors/G0016` headlines “98% weighted coverage” for APT29, which means 65 of 66 techniques have at least one rule in *any* of 13 repos, and “Same behaviour, other vendors” is ATT&CK tag overlap. Until coverage is scoped to my stack and equivalence requires shared observables, it finds rules; it can't back claims.

## 2 · Scorecard

1 = broken or absent · 2 = present but routed around · 3 = works · 4 = better than most peers · 5 = a reason to choose this over grepping the upstream repos.

| # | Dimension | Score | Justification |
|---|---|---|---|
| 1 | Positioning & first-run | 4 | Subtitle states count, repos, schema and ATT&CK mapping in one line; “Last sync today” and “10% rules with no ATT&CK mapping” earn trust. Audience is implied, never stated. |
| 2 | Information architecture | 3 | Detections is clearly primary and every surface deep-links into it. Intel and Digest overlap; `/integrations` is a redirect to `/intel`; seven top-level items. |
| 3 | Search & query UX | 3 | URL-addressable facets, typeahead and inline parse errors are 4-grade. Silent zero results on bad actor, enum and wildcard values (DX-04, DX-07) and docs that don't match behaviour (DX-12) pull it down. |
| 4 | Result density | 3 | Inline expand shows formatted logic without leaving the table. No ATT&CK technique or modified-date column (DX-17). |
| 5 | Rule detail completeness | 4 | Upstream link, license with plain-English restriction, created/updated/synced, raw source, git history, FPs, required fields. Drops deploy prerequisites (DX-16); dates render a day early (DX-09). |
| 6 | Data integrity & normalization | 2 | 855 Splunk rules tagged Linux, at least 626 of them Windows rules (DX-06); 588 Panther/PyPanther title pairs uncounted as duplicates; upstream mis-tags passed through; three counts for T1055. |
| 7 | Coverage claim honesty | 2 | The three match modes exist but are labelled three different ways, defined only in hover tooltips, headlined as “98%”, and contradicted by the Navigator export (DX-01, 02, 03, 08). |
| 8 | Practitioner value | 3 | Beats grep on T1 (when the CVE is known), T4 and T5. Loses T2 outright. T3 is fast and wrong. |
| 9 | Performance at scale | 4 | Server pagination (25/50/100), list ≈200 ms, facets ≈440 ms, offset 15,650 ≈260 ms, rows painted ≈0.7 s warm; 391 KB JS decoded, code-split. `content:` ≈1.4 s; four API calls duplicated per load. |
| 10 | Accessibility | 3 | Real checkboxes, skip link, visible focus ring. Facet counts at 2.5:1, sub-24px targets, key definitions only in `title` attributes (DX-20). |
| 11 | Crawlability | 3 | Sitemaps for all 15,662 rules, 697 techniques, 1,001 actors plus bot prerender with canonical and OG per rule. Soft 404s, one frozen `lastmod`, no JSON-LD, UA-gated rendering (DX-18). |
| 12 | Programmatic access | 4 | Versioned OpenAPI with deprecation policy and a published rate limit; JSON/CSV/Navigator/observables export; “API URL” button. No `license` field, no source-scoped layers, no native-format bundle. |
| 13 | Site security posture | 2 | No CSP, Referrer-Policy or Permissions-Policy; HSTS only on `/api`; floating `swagger-ui-dist@5` script with no SRI; no security.txt (DX-13). |
| 14 | Mobile & responsive | 3 | Table-to-cards is the right call. Search input shrinks to 53 px; actor page scrolls sideways at 390 px (DX-21). |
| 15 | Trust & content ops | 4 | Methodology page is exemplary (pinned SHAs, globs, drift alerting, severity provenance). It contradicts the headline count (DX-10); no site changelog; contact is GitHub or LinkedIn only. |

## Task runs

Each run end to end in the site's own UI, with the API used only to confirm counts. Times are estimates for a practitioner on the same path; my runs were agent-driven. {{product}} for T1 was set to Citrix NetScaler (CVE-2025-5777, “CitrixBleed 2”).

### T1 · New CVE for Citrix NetScaler: which rules, which SIEM?

**Outcome:** BEATS GREP · IF YOU HAVE THE CVE  
Path **/detections → type CVE-2025-5777 → Enter** · Interactions **3** · Time **< 30 s** · Dead ends **1**

Two results, both `SPLUNK · SPL`: “Citrix ADC and Gateway CitrixBleed 2 Memory Disclosure” and “Cisco Secure Firewall – Citrix NetScaler Memory Overread Attempt”. The source badge answers “which SIEM” in the row. Searching the product instead (`citrix`) returns 63; the first dozen are right, then Elastic Protections rules where Citrix appears only in an exclusion list (DX-12). There is no `cve:` field and no product facet, so Sigma's `cve.2021-38647` tags and Splunk's CVE fields aren't normalized.

### T2 · Elastic shop: Sigma rules for T1055 with no Elastic equivalent

**Outcome:** DEAD END  
Path **tech:T1055 source:sigma → per-rule “Same behaviour” panel → /compare** · Interactions **40+** · Time **> 30 min** · Dead ends **3**

`tech:T1055 source:sigma` gives 37 (parent only). `tech:T1055*` silently gives 0. The per-rule equivalence panel matches on technique tags (DX-02), `/compare` needs hand-picked IDs, and `/api/v1/compare/coverage-gap` answers at technique level only. Two cloned repos plus grep on pipe names and process names is faster.

### T3 · Leadership: our APT29 coverage story from public rules

**Outcome:** FAST · MISLEADING  
Path **/actors → APT29 → Export Navigator layer** · Interactions **2** · Time **≈ 15 s** · Dead ends **0**

The page says 98%, 1 gap of 66, 33 exact rules. The exported layer paints 47 of those 66 techniques near the “0 rules – detection gap” red (DX-03). The query bar says `actor:APT29` = 31, not 33 (DX-04). Nothing scopes the story to the SIEM the org actually runs.

### T4 · Deploy one rule: source, license, last sync, FPs

**Outcome:** BEATS THE UPSTREAM REPO  
Path **result row → rule page** · Interactions **1–2** · Time **≈ 30 s** · Dead ends **0**

On the OMIGOD Sigma rule, every answer sits on one page: View source, License “DRL 1.1”, “Synced 9/10/2026”, false-positive notes, and a History tab of upstream commits. Three defects: the header dates are a day early (DX-09), Upstream links to a moving branch (DX-15), and the Zeek prerequisite in `logsource.definition` never appears outside the raw view (DX-16).

### T5 · What changed upstream in 30 days that I should care about?

**Outcome:** DIGEST WINS · INTEL MISLEADS  
Path **/digest → 30D → Copy as markdown** · Interactions **2** · Time **≈ 1 min** · Dead ends **1**

The Digest splits new vs updated per source and themes them by technique, with week permalinks and RSS. `/intel` “Trending techniques” leads with T1219 at 599 because LOLRMM accounts for 597 of 1,176 modifications (DX-14). Neither separates a logic change from a metadata edit.

## 3 · Findings

Ordered by severity, then by reach. Every block cites the page and the element or response observed.

Severity: `P0` credibility-damaging or actively misleading · `P1` blocks a core task · `P2` friction users route around · `P3` polish

### P0 · coverage claims

#### DX-01 · [P0] Actor pages headline a “weighted coverage” percentage the data can't support

- **URL:** `https://detectionexplorer.io/actors/G0016 · /actors/S0154 · /actors`
- **Observed:** The APT29 header renders **“WEIGHTED COVERAGE 98%”** at display size beside “DETECTION GAPS 1/66”. The only definition is a `title` tooltip on the small “raw: 65/66 (98%)” line: “Raw coverage counts every technique equally; the weighted score discounts TTPs nearly every actor uses.” Nothing says that “covered” means one rule in any of 13 repos carries the technique tag. “Coverage by source” rows read “SUBLIME 3/66 · 1226 rules”; the COVERAGE match mode counts 5,063 rules for APT29. Cobalt Strike shows 97% and 4,028. The `/actors` table sorts by this column (APT29 98%, Lazarus 94%, Scattered Spider 94%).
- **Impact:** The T3 answer that gets pasted into a deck is “98% APT29 coverage”. It measures technique-tag presence across products the org doesn't run, including hunting queries, alert passthroughs and hash lists (DX-05), and says nothing about procedure-level detection. That's the exact overstatement ATT&CK heatmaps are criticised for, published under a security-engineering brand.
- **Fix:**
  - Rename to “Techniques with ≥1 public rule (any vendor)”; demote the percentage to secondary text; print the definition under it, visibly.
  - Make the dedicated (named) rule count the primary stat.
  - Add a “My stack” source selector, persisted as `?sources=`, that recomputes gaps and coverage for the chosen repos.
  - Exclude hunting, building-block and passthrough rules from coverage by default, with a visible toggle.
- **Unverified:** The weighting formula; only the tooltip text is exposed.
- **Effort:** S / M
- **Confidence:** High

#### DX-02 · [P0] “Same behaviour, other vendors” is ATT&CK tag overlap, not behaviour

- **URL:** `https://detectionexplorer.io/detections/3cfc23e0-7022-51ac-8e05-04cb43afff19 (Sigma, OMIGOD) · https://detectionexplorer.io/detections/4dd04229-e9e2-5e95-b1c0-7622a02bf8c6 (Sigma, CobaltStrike Named Pipe)`
- **Observed:** The OMIGOD panel lists “12 rules · 4 other sources”, including Sentinel “GitHub Security Vulnerability in Repository”, “Apache 2.4.49 flaw CVE-2021-41773” and “Sentinel One – Same custom rule triggered on different hosts”, each justified only by “technique T1190, T1210”. For CobaltStrike Named Pipe, which keys on `\MSSE-` and `\postex_`, `/api/v1/detections/{id}/related` returns one other-vendor match: “Memory Threat – Detected – Elastic Defend”, reason “technique T1055”. Meanwhile `content:"MSSE-"` finds Sentinel “Suspicious named pipes”, which keys on the same pipe, and it isn't surfaced.
- **Impact:** **[B]** This panel is the porting workflow. It tells an Elastic shop that an alert-forwarding rule is the equivalent of a Sigma named-pipe rule. A DE who trusts it closes a gap that is still open.
- **Fix:** Label a row “same behaviour” only when at least one non-negated observable overlaps (pipe or file name, process, registry key, API action, event ID), and print it on the row: “both key on `\MSSE-`”. Move technique-only matches to a collapsed “Shares an ATT&CK technique” group.
- **Unverified:** Why the Sentinel rule was missed (extraction on that rule or the scorer).
- **Effort:** S
- **Confidence:** High

#### DX-03 · [P0] The Navigator layer export paints covered techniques in the “gap” colour

- **URL:** `https://detectionexplorer.io/api/v1/actors/G0016/navigator-layer (the [ EXPORT NAVIGATOR LAYER ] button on /actors/G0016)`
- **Observed:** Linear gradient `#ff0040 → #ffaa33 → #00ffcc` over 0–829, where 829 is T1566.002. Legend: red = “0 rules – detection gap”. 47 of 66 techniques score below 83 (10% of max); the median is 30. T1003.002 with 55 rules renders effectively as a gap. The page it came from says 98%. The endpoint takes only `actor_id` and `match_mode`, so there's no “Elastic only” layer.
- **Impact:** The one artifact built for leadership contradicts the page in the opposite direction. Whichever view gets presented, someone is misinformed.
- **Fix:** Score in bins (0 · 1 · 2–5 · 6–20 · 21+) with one legend entry per bin, or cap `maxValue` at 20. Add `sources=` and `exclude_modalities=`. Write the match mode, source scope and sync SHAs into the layer `description`.
- **Effort:** S
- **Confidence:** High

### P1 · blocks a core task

#### DX-04 · [P1] Actor lookup returns silent zeros and disagrees with the actor page

- **URL:** `https://detectionexplorer.io/detections?q=actor:%22Mustang%20Panda%22 · /actors/G0129 · /actors/G1014 · /actors/G0016`
- **Observed:** `actor:"Mustang Panda"` → 0. `actor:G0129` → 1. The `/actors` table shows Mustang Panda with 3 dedicated and 9 referenced. LuminousMoth (G1014) lists “MUSTANG PANDA · BRONZE PRESIDENT” among its MISP aliases, and `actor:"BRONZE PRESIDENT"` → 0 as well. `actor:APT29` → 31; the APT29 page says 33. Typos (`actor:"Salt Typoon"`, `actor:APT-29`) and bad enum values (`severity:hgih`) return 200 with “NO DETECTIONS FOUND”, while an unknown field (`foo:bar`) does raise `query_parse_error`. Validation exists; it just stops at field names.
- **Impact:** T3 run from the query bar reports “no public rules for Mustang Panda”: a false gap, and it reads as missing coverage rather than a lookup failure.
- **Fix:** One resolver for the query bar and actor pages. When an alias maps to more than one group, show a chip: “Mustang Panda → G0129 (also an alias of G1014)”. Return `query_value_error` with a suggestion for unknown actor, software and enum values, rendered inline like the parse error. Add a test asserting equal counts for the top 50 groups.
- **Unverified:** That the alias collision is the root cause (inferred from the alias data).
- **Effort:** S–M
- **Confidence:** High

#### DX-05 · [P1] Alert passthroughs, hash lists and upstream mis-tags count as technique coverage

- **URL:** `https://detectionexplorer.io/mitre/T1055`
- **Observed:** Sentinel's T1055 list includes “TrendAI Vision One – Create Incident for Workbench Alerts”, “Google SecOps – Multi-Event Correlated Alert” and “CYFIRMA – Medium severity File Hash Indicators with Block Action and Malware”. Elastic's includes “Memory Threat – Detected – Elastic Defend”. Splunk's includes six “AWS Bedrock Claude …” rules (e.g. “Hostile Prompt Sentiment”); the upstream YAML does say `mitre_attack_id: T1055`, and the site passes it through unflagged.
- **Impact:** Process-injection “coverage” includes rules that forward another product's alert or match hashes, and these feed the DX-01 percentages.
- **Fix:** Classify rules whose event type is `platform_alert`/`siem_alert`, or whose only observables are indicators, as modality `passthrough`/`indicator`; exclude them from coverage by default. Add a build lint that flags technique-platform vs rule-domain mismatches (T1055 is Linux/macOS/Windows; the Bedrock rules are cloud/application) with a “suspect mapping” badge and a count on corpus-health.
- **Effort:** M
- **Confidence:** High

#### DX-06 · [P1] Splunk rules inherit every OS their data sources support

- **URL:** `https://detectionexplorer.io/detections?q=platform:linux%20source:splunk · /detections/d27b3d4a-8681-5039-8131-5c0f72e76963`
- **Observed:** “Windows SQLCMD Execution” (`detections/endpoint/windows_sqlcmd_execution.yml`) carries platforms `windows, linux, macos`, alongside data sources `carbon_black, crowdstrike_fdr, elastic_defend, sysmon, windows_security_event_log`. `sources=splunk&platforms=linux` → 855 of 2,166 Splunk rules; adding `search=windows` → 626 of those. The Linux facet total is 2,202, so Splunk is 39% of it and at least 28% of it is Windows rules.
- **Impact:** A Linux-focused team filtering `platform:linux` triages hundreds of Windows rules; the “Linux” and trending-platform counts are inflated.
- **Fix:** For Splunk endpoint rules, derive OS from OS-specific sources in the rule's own `data_source` list (Sysmon, Windows Event Log → windows; Sysmon for Linux, auditd → linux), fall back to the `windows_/linux_/macos_` filename prefix, and stop unioning across CIM datamodel sources.
- **Effort:** M
- **Confidence:** High

#### DX-07 · [P1] T2 — “Sigma for T1055 we don't have in Elastic” — has no path

- **URL:** `https://detectionexplorer.io/detections?q=tech:T1055%20source:sigma · /compare · /api/v1/compare/coverage-gap?base_source=sigma&compare_source=elastic`
- **Observed:** `tech:T1055 source:sigma` → 37, parent only (`/query`: “tech:T1059 matches only T1059, never T1059.001”). `tech:T1055*` → 0 with no error, though `/query` lists `*` as a wildcard. `/compare` needs 2–6 hand-picked IDs. The coverage-gap endpoint returns technique IDs only (Sigma 398, Elastic 450, overlap 327) and isn't in the UI. In the query bar `source:elastic` returns 213 for T1055 (Elastic + Protections + Hunting); the “Elastic” facet returns 27.
- **Impact:** The most common porting question ends in a manual per-rule loop, slower than grepping two repos.
- **Fix:** Support `tech:T1055.*` or an “include sub-techniques” toggle, and error on unsupported wildcards. Add a `no_equivalent_in=elastic` filter backed by the observable-overlap scorer from DX-02, exposed as a facet “Has equivalent in…”. Make `source:elastic` exact and offer `source:elastic*` for the family.
- **Effort:** M–L
- **Confidence:** High

#### DX-08 · [P1] The three match modes are named three different ways

- **URL:** `https://detectionexplorer.io/actors/S0154`
- **Observed:** Header stat “RULES (EXACT) 45”. Toggle “DEDICATED 45 · COVERAGE 4028 · REFERENCED 43”. The page requests `?match_mode=exact`. Row chips read TITLE, STORY, ID-TAG (tooltips “Matched via title”, “Matched via story”); of the first 16 Cobalt Strike rows, one is ID-TAG. Only REFERENCED has an explanatory tooltip.
- **Impact:** “Exact” promises tag-level precision; most matches are title substrings and Splunk analytic stories. The mechanism the site relies on for honesty is illegible to anyone who doesn't already know it exists.
- **Fix:** One vocabulary on stat, toggle, API and docs: **Named** (tag / title / story), **Technique overlap**, **Mentions**. A visible one-line definition under the toggle. Break the named count down by reason, in the form “33 named · *n* tag · *n* title · *n* story”.
- **Effort:** S
- **Confidence:** High

### P2 · friction users route around

#### DX-09 · [P2] Every rule date renders one day early west of UTC

- **URL:** `https://detectionexplorer.io/detections/3cfc23e0-7022-51ac-8e05-04cb43afff19 · /detections/a4523ea0-7463-5d7c-b67f-dfbe27037abe`
- **Observed:** Sigma raw `date: 2021-09-20`, `modified: 2025-11-03` → header “Created … on 9/19/2021 · Updated 11/2/2025”. Elastic raw `creation_date = "2026/08/20"`, `updated_date = "2026/08/26"` → “8/19/2026 · 8/25/2026”. Viewer in America/Toronto. The git History tab shows 2021-09-20 correctly, so the page disagrees with itself.
- **Impact:** T4's “when was it last updated” is wrong for every viewer in the Americas, on a page whose raw source is one click away.
- **Fix:** Date-only values are calendar dates: format with `timeZone: 'UTC'` or split `YYYY-MM-DD` into local components. Print ISO (`2025-11-03`); DEs compare against the YAML.
- **Effort:** S
- **Confidence:** High

#### DX-10 · [P2] The headline count includes what the methodology says it excludes

- **URL:** `https://detectionexplorer.io/ · /methodology`
- **Observed:** Landing: “15,662 detection rules”. Methodology: “hunting content is not counted as detection rules.” The facets put 407 hunting, 239 building-block, 152 correlation and 106 ML-job items inside the 15,662, and Elastic Hunting (141) is a listed source. Panther (877) and PyPanther (595) share 588 exact titles (e.g. “axonius api key reset”) with no shared rule IDs and no cross-link.
- **Impact:** The methodology page is the trust anchor, and the first number on the site contradicts it. Duplicate pairs double-count in coverage and in the equivalence panel.
- **Fix:** Change the sentence to “hunting queries are indexed and tagged `modality:hunting`”, or split the headline (“15,255 rules + 407 hunting queries”). Add `duplicate_of` for Panther↔PyPanther pairs and count each pair once in coverage.
- **Unverified:** Whether all 588 pairs have identical logic.
- **Effort:** S (copy) / M (dedup)
- **Confidence:** High

#### DX-11 · [P2] One technique, three rule counts

- **URL:** `https://detectionexplorer.io/mitre/T1055`
- **Observed:** Matrix cell “T1055 Process Injection 365” (294 tagged exactly + 71 on sub-techniques). Catalog `tech:T1055` → 294. The “Matching detection rules” list shows SIGMAHQ (10), ELASTIC (9), ELASTIC PROT. (158), SENTINEL (8), SPLUNK (13), ELASTIC HUNT (2) = 200, while the vendor summary on the same page says Elastic “27 rules” and the catalog gives Sigma 37, Splunk 32, Sentinel 12, Elastic Protections 184.
- **Impact:** **[B]** Which number goes in the report? On a reference site, unexplained disagreement reads as a bug even when each count is defensible.
- **Fix:** Label each count with its scope (“365 incl. sub-techniques”, “294 tagged T1055”). If the vendor list is truncated, say “showing 10 of 37 · open all in catalog”.
- **Unverified:** What filters produce the 200.
- **Effort:** S
- **Confidence:** High

#### DX-12 · [P2] Bare-word search hits rule bodies, including exclusion lists

- **URL:** `https://detectionexplorer.io/detections?q=citrix · /query`
- **Observed:** `/query`: a bare word is a “substring across title + description + tags”. `citrix` returns 63, including Elastic Protections “Shellcode API behavior from a signed module”, where “citrix” appears only in `detection_logic` inside a list of excluded code-signing vendors. Matching is token-based, not substring: `m` → 135, `a` → 0.
- **Impact:** T1 by product name returns about a dozen relevant rules, then a tail of rules that explicitly ignore the product.
- **Fix:** Scope bare words to title/description/tags as documented and keep `content:` for bodies. For `content:` hits, show a highlighted snippet and mark matches inside negated observables using the existing `negated` flag. Correct “substring” to “word” in the docs.
- **Effort:** S
- **Confidence:** High

#### DX-13 · [P2] A security site without security headers, running a floating CDN script on its origin

- **URL:** `https://detectionexplorer.io/ · /api/docs · /.well-known/security.txt`
- **Observed:** HTML responses send `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and the deprecated `X-XSS-Protection`. No `Content-Security-Policy`, no `Strict-Transport-Security` (API responses do send `max-age=63072000`), no `Referrer-Policy`, no `Permissions-Policy`. `/api/docs` loads `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`, a floating major with no `integrity`. `/.well-known/security.txt` returns the SPA shell as 200 text/html. Pages load both Cloudflare RUM and Vercel Insights; neither is mentioned on /about.
- **Impact:** This audience runs header scanners on sites they cite. A weak grade becomes the story, not the rules.
- **Fix:** `vercel.json` headers: CSP (`default-src 'self'; script-src 'self' static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`), HSTS with `includeSubDomains`, `Referrer-Policy: strict-origin-when-cross-origin`, a minimal `Permissions-Policy`. Pin swagger-ui to an exact version with SRI or self-host it. Publish a real security.txt. One sentence on analytics in /about.
- **Unverified:** Headers read via same-origin fetch from a browser (all non-cookie headers are exposed). Bundle dependency versions not audited.
- **Effort:** S
- **Confidence:** High

#### DX-14 · [P2] Intel “trending” is one repo's bulk rewrite

- **URL:** `https://detectionexplorer.io/intel · /api/v1/trending/summary?days=30`
- **Observed:** 30-day pulse: 196 new, 1,176 modified. LOLRMM accounts for 597 of the modifications (51%). Trending #1 is “T1219 Remote Access Tools 599”; #2 is T1566.002 at 90.
- **Impact:** T5's answer from /intel is “LOLRMM regenerated its files”. The signal a DE wants (new logic for a technique they care about) is buried.
- **Fix:** Rank trending on new rules plus logic-changed rules. Classify each modification as logic, metadata or cosmetic by hashing normalized `detection_logic` between syncs, and collapse commits touching more than N files into one line.
- **Unverified:** That the LOLRMM modifications are cosmetic.
- **Effort:** M
- **Confidence:** High

#### DX-15 · [P2] Upstream links point at moving branches, and the branches disagree with the methodology

- **URL:** `https://detectionexplorer.io/detections/a4523ea0-7463-5d7c-b67f-dfbe27037abe · /methodology`
- **Observed:** Methodology lists `elastic/detection-rules @master` (pinned `ffc8ad66`) and `splunk/security_content @master` (pinned `4cd62e81`). The Elastic rule's “Upstream ↗” goes to `…/detection-rules/blob/main/…`; Splunk `source_rule_url` values go to `…/security_content/blob/develop/…`.
- **Impact:** T4 license review and diffing happen against a file that may be newer than the one indexed.
- **Fix:** Primary link to `/blob/<pinned-sha>/path` labelled “as indexed”; secondary “latest on <branch>”. Print the real branch name in the methodology table.
- **Effort:** S
- **Confidence:** High

#### DX-16 · [P2] Normalization drops the deploy prerequisites

- **URL:** `https://detectionexplorer.io/detections/3cfc23e0-7022-51ac-8e05-04cb43afff19`
- **Observed:** Raw Sigma `logsource.definition`: “Enable the builtin Zeek script that logs all HTTP header names by adding `@load policy/protocols/http/header-names`…”. The Definition panel shows source tables, data source, required fields; the prerequisite appears only in raw view. The Elastic rule's `integration = ["network_traffic", "fortinet_fortigate", "zeek"]` isn't presented as setup either.
- **Impact:** **[B]** Without that Zeek script, `client_header_names` never exists and the OMIGOD rule never fires. Missing prerequisites are the most common reason a public rule is silently dead in production.
- **Fix:** A “Before you deploy” block built from Sigma `logsource.definition`, Elastic `integration`/`setup`/`min_stack_version`, Splunk `how_to_implement`. Index it for search.
- **Unverified:** Elastic `setup` field handling on that rule.
- **Effort:** S–M
- **Confidence:** High (Sigma)

#### DX-17 · [P2] The rule table omits the two columns DEs triage on

- **URL:** `https://detectionexplorer.io/detections`
- **Observed:** Columns: Title, Source, Severity, Domain, Data Source, Event Type, Created, Completeness. No ATT&CK technique, no Modified. The inline expand shows logic but not techniques.
- **Impact:** Coverage and recency triage cost a detail-page round trip per row.
- **Fix:** Add “Techniques” (first two IDs + “+n”, monospace, linked to `/mitre/`) and “Modified” (relative, ISO on hover). Fold Domain into the Data Source cell as a prefix to hold width.
- **Panel split:**
  - **[A]** Nine columns crowd the 692 px breakpoint; swap Completeness for Techniques rather than add both.
  - **[B]** Techniques is non-negotiable; Completeness can move to the expand row. Agreed resolution: swap.
- **Effort:** S
- **Confidence:** High

#### DX-18 · [P2] Crawl hygiene: soft 404s, a frozen lastmod, UA-gated rendering

- **URL:** `/sitemap-detections.xml · /nonexistent-page-xyz · /detections/not-a-real-id-xyz · /integrations · /api/v1/prerender/detection/{id}`
- **Observed:** Every unknown path returns 200 with the 2,495-byte shell. All 15,662 detection URLs share one `lastmod` (2026-09-10). `/integrations` is in the sitemap and redirects client-side to `/intel`. Prerender covers detection, technique, actor, home and corpus-health: per-rule title, canonical, OG and logic, but no JSON-LD and no license or upstream link. A generic fetcher receives the empty shell. `/detections`, `/actors`, `/intel`, `/about`, `/actors/heatmap` all title as “Detection Explorer”. A `site:` query in my search tool returned no pages (not Google; check Search Console).
- **Impact:** Search engines discount a lastmod that changes daily for every URL; soft 404s waste crawl budget and deleted rules never drop out. Individual rule pages are the organic-growth engine.
- **Fix:** Serve the SPA with status 404 for unknown routes and missing IDs at the edge. Set `lastmod` from `rule_modified_date`. Drop `/integrations` or 301 it. Prerender `/methodology`, `/digest/*`, `/query`, `/observables/*`. Add JSON-LD (`TechArticle` with `license`, `dateModified`, `isBasedOn` = upstream URL). Route-level titles.
- **Unverified:** What Googlebot receives; the browser can't set a crawler User-Agent, so the prerender endpoint was fetched directly.
- **Effort:** M
- **Confidence:** Med

#### DX-19 · [P2] Removed or unknown rules show a raw client error

- **URL:** `https://detectionexplorer.io/detections/00000000-0000-5000-8000-000000000000`
- **Observed:** Body: “Error loading detection: Request failed with status code 404”; title stays “Detection Explorer”; HTTP 200. The empty-results state reads “Try adjusting filters or sync repositories”, and syncing is an admin action. Vendor-ID permalinks do work: `/api/v1/detections/ab6b1a39-…` redirects to the canonical rule.
- **Impact:** The permalink guarantee holds for live rules, but a rule deleted upstream becomes a dead end with developer copy.
- **Fix:** Keep tombstones (id, title, source, last-seen SHA, removal date) and render “Removed upstream on YYYY-MM-DD (commit …) — last indexed version · similar rules”. Empty state: “No rules match. Remove a filter or check the query syntax.”
- **Effort:** M (tombstones) / S (copy)
- **Confidence:** High

#### DX-20 · [P2] Small secondary text fails AA contrast on the dark theme

- **URL:** `https://detectionexplorer.io/detections`
- **Observed:** Facet counts: `#4B5563` on `#0D1117` at 10 px = 2.50:1. “SORT:” and header sub-labels: `#6B7280` on `#010409` at 10–12 px = 4.25:1. Row titles are fine (14.6:1). Focus ring is visible, facet options are real checkboxes, skip link present. Rows have three tab stops each, so 75 Tabs to reach pagination. Coverage definitions live in `title` attributes.
- **Fix:** Facet counts to `#8B94A3` at 11 px (≥5:1); secondary labels to `#9AA3B2`. One tab stop per row with arrow-key roving, or `j`/`k`. Replace definition tooltips with visible text or a disclosure.
- **Effort:** S
- **Confidence:** High

#### DX-21 · [P2] At 390 px the search box is 53 px wide and the actor page scrolls sideways

- **URL:** `https://detectionexplorer.io/detections?q=tech:T1055 · /actors/G0016 (390 × 844)`
- **Observed:** The table correctly becomes cards with filter chips. The search input measures 53 px (“tech:T” visible) beside ★ and SYNTAX. Clear-query is 10 × 16 px and “clear all” 59 × 15 px, under WCAG 2.2's 24 px target minimum. On `/actors/G0016` the “Rules (exact)” stat spans x = 344–428, widening the layout to 429 px.
- **Fix:** Below 480 px, move ★ and SYNTAX under the input or into its menu; input full width. Stat row as a 2 × 2 grid. 24 × 24 minimum hit areas.
- **Effort:** S
- **Confidence:** High

### P3 · polish

#### DX-22 · [P3] Polish bundle

- **Items:**
  - **/detections inline logic:** JetBrains Mono ligatures render SPL `Processes.action!="blocked"` as ≠ (copied text is correct). Set `font-variant-ligatures: none` on code.
  - **/intel:** pulse bars label three Elastic sources “ELA” (37, 17, 1); What's New truncates severity to “MEDI”; upstream releases repeat the tag (“v6.6.0 v6.6.0”).
  - **Severity vocabulary:** table “UNKNOWN”, facet “Not Specified”, methodology “not specified”. Pick one.
  - **/observables/process:** “Top process values” is ordered by source count, not rules (msedge.exe 62 sits above cmd.exe 374). Label the sort.
  - **Request fan-out:** each /detections load makes 10 API calls; `/mitre`, `/query/fields`, `/detections/filters`, `/query/event-ids` each fire twice. Against 40 req/10 s per IP, a SOC behind one NAT hits the limit sooner.
  - **Tabs:** Details / Investigation guide / History on rule pages aren't in the URL.
  - **OG images** live under `/api/og/`, which robots.txt disallows; crawlers that honour robots for card images may drop previews. Confidence Med.
  - **Theme:** dark-only, no `color-scheme` declaration.
    - **[A]** Deliberate and right for a scanning tool; don't build a light theme.
    - **[B]** The leadership export gets projected and printed. Resolution: make exports and a print stylesheet light, leave the app dark.
- **Effort:** S each
- **Confidence:** High unless noted

### Choices that look wrong but hold up

- **Empty-query “Relevance” interleaves sources round-robin** (Splunk, Sublime, Sentinel, Elastic…). Correct as a first-visit sampler that shows breadth. Keep it limited to the empty query, as it appears to be now (`q=citrix` ranks title matches first).
- **UA-based prerender instead of SSR.** Correct for a solo maintainer on a Vite SPA, as long as the bot list includes Google, Bing and the AI crawlers you want citing you, and content parity holds.
- **Enter-to-submit, no live search.** Correct while `content:` queries take ≈1.4 s.

## 4 · Missing table stakes

What a professional security reference tool is expected to have, judged against a named peer that has it.

| Gap on detectionexplorer.io | Peer that has it | Why it matters here |
|---|---|---|
| Convert a displayed Sigma rule to the reader's backend (ES\|QL, KQL, SPL) | SigmaHQ's sigconverter.io (pySigma backends) | T2 ends with “now write it in Elastic”. The site already holds 4,406 Sigma-language rules. |
| Import your own layer or rule inventory and diff against it | MITRE ATT&CK Navigator (open existing layer, layer-by-operation) | “Coverage” without “ours” is the DX-01 problem. |
| Per-rule setup: required integrations, prerequisites, minimum version | Elastic detection rule docs (Setup and related integrations per rule) | DX-16: the rule page shows fields but not what must be switched on. |
| “How to implement” and linked test data | Splunk Research detection pages (implementation notes, attack_data test datasets) | The completeness score reads testability (17/20 on Windows SQLCMD Execution) but the page shows no test-data link. |
| Match highlighting in results | Sourcegraph (highlighted line matches per result) | DX-12: you can't tell an exclusion from a detection without opening the rule. |
| Inline diff between indexed versions of a rule | Sourcegraph / GitHub commit diffs | The History tab lists commits; T5 needs “what changed in the logic”. |
| Product changelog | Grafana “What's new”, Sourcegraph changelog | `/changelog` is a soft 404; API changes are only announced on GitHub. |
| Shareable, named saved searches | Sourcegraph saved searches | ★ saves to this browser only (`tde.search.recent` in localStorage). |

## 5 · Detection-engineering value gaps

**[B · DETECTION]** leads. What turns a bookmark into a daily driver.

| Capability | State | What exists | What makes it daily-driver |
|---|---|---|---|
| Gap vs. my stack | MISSING | Technique-level `/compare/coverage-gap` in the API only. | A “My stack” source set stored in the URL and applied to actor, MITRE, heatmap and Navigator views, plus paste-or-upload of my rule IDs (Sigma `id`, Elastic `rule_id`) returning the public rules I don't have. |
| Rule diffing across sources | PARTIAL | `/compare?ids=` observable diff with exclusions marked. Good. | Pre-select the pair from an observable-gated equivalence finder (DX-02) so nobody has to already know both IDs. |
| ATT&CK Navigator export | PARTIAL | Per actor, per software and from catalog export. | Binned scoring, source scope, provenance in `description` (DX-03). |
| Data-source requirement filtering | STRONG | 146 data sources, parent/child event types, 212 products as facets. | Invert it: save “I have Sysmon + CloudTrail + Okta” as a profile and show what I can run today. |
| False-positive intelligence | PARTIAL | Upstream FP text per rule; corpus-health counts rules with no FP notes. | FP themes per technique and a “no FP guidance” filter in the catalog. |
| Deploy-ready export per SIEM | PARTIAL | JSON, CSV, Navigator, observables CSV, optional raw content. | Zip of native files with upstream paths plus a LICENSES manifest. `license` is absent from both the API detail object and the CSV columns today. |
| Saved queries | PARTIAL | Star and recent, per browser. | Named, shareable collections (a URL list is enough) and an RSS feed per saved query. |
| Coverage export for leadership | MISSING | Nothing beyond the layer. | A one-page, print-light export stating source set, match mode, exclusions, sync date and pinned SHAs. The methodology page already has every number it needs. |
| Change classification | MISSING | New vs modified. | Logic / metadata / cosmetic per modification (DX-14), filterable in Digest. |

## 6 · Prioritized backlog

Ranked by (practitioner impact × reach) ÷ effort for one maintainer. Items 1–6 fit in about a week of evenings.

| Rank | Item | Dimension | Impact | Effort | Why now |
|---|---|---|---|---|---|
| 1 | Relabel actor coverage: “techniques with ≥1 public rule”, visible definition, named count as primary stat (DX-01, DX-08) | 7 Coverage honesty | High | S | Copy and layout only, and it's on every actor and software page today. |
| 2 | Gate “Same behaviour” on shared observables; move tag-only matches to their own group (DX-02) | 7 · 6 | High | S | The scorer already returns reasons; this is a threshold and a label on every rule page. |
| 3 | Fix date-only parsing (DX-09) | 5 Rule detail | Med | S | One formatter, all 15,662 rule pages, and it's the first thing a DE checks against the raw YAML. |
| 4 | Navigator layer: binned scores, `sources=`, provenance in description (DX-03) | 7 · 12 | High | S | It's the artifact that leaves the site. |
| 5 | One actor resolver + `query_value_error` for unknown actor, software and enum values (DX-04) | 3 Search | High | S–M | Silent zeros read as “no coverage”; the error path already exists for unknown fields. |
| 6 | Security headers, pinned Swagger UI with SRI, security.txt (DX-13) | 13 Security | Med | S | One `vercel.json` change; the audience will scan it. |
| 7 | Techniques and Modified columns in the table (DX-17) | 4 Density | Med | S | Removes a round trip from every triage session. |
| 8 | Splunk OS derivation from rule data sources and filename (DX-06) | 6 Integrity | Med | M | Corrects the platform facet, trending platforms and every OS-scoped coverage number at once. |
| 9 | Crawl hygiene: real 404s, real `lastmod`, JSON-LD, prerender for methodology/digest/query (DX-18) | 11 Crawlability | Med | M | Rule pages are the growth engine and the sitemap currently tells crawlers everything changed today. |
| 10 | T2 workflow: sub-technique rollup in `tech:` and a “has equivalent in…” facet (DX-07) | 8 Value | High | M–L | Depends on #2's scorer; it's the feature that makes an Elastic or Sentinel shop open the site every week. |

## 7 · Protect in a redesign

Specific things both reviewers would fight to keep.

### Facets and query are one model

Ticking Sigma and High writes `?q=source:sigma severity:high`; refresh, back and share preserve it, and sort lands in the URL too. “API URL” copies the exact call (`/api/v1/detections?q=…&sort_by=…`). Don't let a redesign split filter state from the query.

### Provenance on the rule page

License with its consequence spelled out (“ELv2 — Elastic License 2.0: no managed-service redistribution”), Created / Updated / Synced, raw source, a History tab of upstream commits, and vendor-ID URLs that redirect to the canonical page.

### The methodology page

Per-source include globs, excluded directories, pinned SHA, 5% drift alerting and severity provenance (“never a default dressed as data”). Almost no aggregator publishes this; it's the right place to also state the coverage definition.

### The weekly Digest

Week permalinks (`2026-w37`), 7 / 14 / 30-day windows, new vs updated per source, technique themes, copy-as-markdown and RSS. The best T5 surface on the site; a better home for “what changed” than the Intel trend panels.

### An API contract a DaC pipeline can depend on

`/api/v1` with a six-month deprecation window and 30-day notice, a published rate limit (40 req / 10 s), stated cache and sync timing, and an OpenAPI schema. Plus a completeness score explicitly framed as “not whether it catches the attacker”.

## Method & limits

What was assessed, and what couldn't be checked from this position.

| Surface | URLs assessed |
|---|---|
| Landing & nav | / · /about · /methodology · /query · /compare · /integrations (→ /intel) |
| Catalog | /detections · ?q=cve-2025-5777 · ?q=citrix · ?q=tech:T1055 · ?q=(source:sigma%20AND · ?q=tech:T1055%20source:okta · ?q=source:sigma+severity:high&offset=25 |
| Rule detail, 3 sources in UI | Sigma /detections/3cfc23e0-7022-51ac-8e05-04cb43afff19 · Splunk /detections/d27b3d4a-8681-5039-8131-5c0f72e76963 · Elastic /detections/a4523ea0-7463-5d7c-b67f-dfbe27037abe · via API: Okta 53c73733-…, Sentinel 0f616728-…, Sigma 4dd04229-… |
| Actors & ATT&CK | /actors · /actors/G0016 · /actors/S0154 · /actors/heatmap · /mitre/T1055 · /observables/process |
| Intel | /intel · /digest |
| Technical | /robots.txt · /sitemap.xml + 4 children · /api/docs · /api/openapi.json · /api/v1/prerender/detection/{id} · /.well-known/security.txt · response headers on / and /detections |

- The cloud sandbox's egress policy blocks detectionexplorer.io, so everything ran in the in-app Chromium pane on the user's machine: UI interaction, same-origin `fetch` for headers and API, computed-style contrast, `PerformanceObserver` timings.
- Viewports tested: 692 px native pane, 1280 × 800 emulated, 390 × 844 mobile emulation; `prefers-color-scheme: light` emulated.
- Not verified: what Googlebot receives (User-Agent can't be set from page JS); cold-cache load times (warm cache only); Lighthouse, screen-reader output and `prefers-reduced-motion` behaviour (one reduced-motion rule found in CSS). No 429s were hit across well over 100 API calls.
- No finding relies on a guess. Where a cause is inferred rather than observed, the finding says so under “Unverified”.

---

_Detection Explorer panel review · assessed against build 7f51b8a and the 2026-09-10 corpus sync._  
_Counts quoted from the live site and `/api/v1` on the same day; they will drift with the nightly sync._
