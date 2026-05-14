# Detection Explorer Roadmap

**Single source of truth.** Anything that contradicts this doc is wrong or
stale. For shipped work, see [`CHANGELOG.md`](../CHANGELOG.md). This doc
replaces both the old `REVIEW_AND_ROADMAP.md` and the Intel-page-specific
`intel-roadmap.md` — everything load-bearing from those is folded in here.

---

## What this project is for

> A continuously updated, vendor-agnostic view of what open-source detection
> content covers — optimized for engineers deciding where to spend their next
> hour.

Every feature should serve that. *AI assistant for detection engineers* is a
different product — see [Deferred](#deferred) below.

---

## Recently shipped (last 30 days)

Top items only. Full history lives in [`CHANGELOG.md`](../CHANGELOG.md).

- **Pipeline audits, Phase 2 (normalization)** —
  `scripts/audit_normalization.py` paginates the production API and
  measures per-source classification quality: taxonomy distributions,
  `cross_platform` / `[unknown]` rates, no-observables, no-MITRE,
  legacy-vs-canonical disagreement, and language-sanity. Heuristic
  thresholds flag anomalies. First run surfaced three issues worth
  fixing: Sentinel `cross_platform` 50.1%, Sentinel `unknown_platform`
  14.2%, and 4 elastic_hunting rules with an unexpected `SQL` language
  tag. Findings tabulated in [`docs/audit.md`](./audit.md).
- **Intel + Compare pages hidden from nav/routes** — both pages need
  rework before re-exposure; routes redirect to `/` so bookmarks don't
  404; render-smokes still pass (`7199d83`). See
  [Hidden pages](#hidden-pages--restore-when-reworked).
- **Foundation pay-down cycle II** — six items finishing the foundation
  work. `/trending/threats` accepts an optional `days` filter
  (`a9688da`); the IndustryIntel page threads its existing period
  selector into Threat Pulse so all four trending sections share one
  user-controlled window. SearchService now has 26 integration tests
  covering every filter dimension, including the JSON-array
  quoted-substring guard that prevents `T1059` from false-positiving
  onto `T1059.001` (`21e97a2`). IngestionService gets 10 tests pinning
  the atomic-swap pattern and proving that a crash before cleanup
  preserves old rows (`423da10`). Vitest render-smokes added for
  MitreCoverage (`423da10`), DetectionList, and Compare (`61653dd`) —
  page-render coverage now spans the four most state-heavy pages.
  IndustryIntel decomposed from a 754-line god-component into a
  116-line composition + 8 sub-modules under `pages/intel/` with
  behavior preserved (covered by the existing render smoke).
  Backend totals: 275 tests. Frontend: 10 tests.
- **Foundation pay-down cycle I** — eight stability/perf items in one push.
  `datetime.utcnow()` deprecated → naive `utcnow()` helper across 33 call
  sites (`a571a6e`). Trending routes column-scoped, no more loading the
  full Detection row when 3–4 columns suffice (`439eb4a`). Splunk
  normalizer preserves the `story:` prefix and drops asset/domain noise
  (`7a3a28b`). `sourceConfig` redefined in 6 files + `clipPath` inlined
  30× → centralized in `constants/style.ts` (`0284891`). Route-level
  `React.lazy` — initial bundle **1.5 MB → 283 KB** (`1ecf6c1`). Parser
  `can_parse()` substring bug (filename `test.toml` matched the `test`
  exclusion) → path-parts match; 5 broken parser tests fixed (`6d7c2a0`).
  Vitest + jsdom + 5 first tests including a render-smoke for IndustryIntel
  that catches the hook-order class of bug (`e598c01`). Parser date
  backfill confirmed shipped — was local-DB drift, not a prod bug
  (`837bca9`).
- **Roadmap consolidation** — three planning docs merged into a single
  `docs/roadmap.md`. `REVIEW_AND_ROADMAP.md` + `docs/intel-roadmap.md`
  deleted (`91a05b7`).
- **Intel page rebuilt around industry signal** — Pulse banner, Threat Pulse
  (named threats from Splunk `analytic_story` + Sublime `Malfam:` tags, no
  hardcoded list), CVE Watch, restyled Upstream Releases, demoted trending
  rows. New `/trending/threats` endpoint. Commits `cf014d8` + `46b9b1e`.
- **MITRE ATT&CK browser** — left tactic tree / right detail layout with
  per-technique drill, MITRE-sourced metadata, matching rules grouped by
  source, deep-linkable `/mitre/:techniqueId`. Commit `d1fbbd3`.
- **Parser DRY pass** — `BaseParser._validate_rule_shape()` folds the
  `isinstance + title + logic` boilerplate every parser duplicated.
  Commit `ff72148`.
- **Sentinel taxonomy + unknown-tag sweep** — tiered resolver lifted Sentinel
  coverage 79.9 % → 97.8 %. EQL sequences, KQL extraction, alerts-* platform
  inference, Splunk macros. Commits `0891591`, `dcb7afe`, `cb82181`,
  `f754d87`.
- **Detections page filter rewrite** — FilterPanel 799 → 492 lines via
  `TelemetryFilter`, `TagInputFilter`, `ActiveFilterPills` decomposition.
- **Worker / API split** — `JobQueueService` with atomic claim semantics,
  stuck-job sweep, isolated worker process on Railway. Earlier shipping but
  still load-bearing infrastructure.
- **Field extraction across 6 query languages** — Sigma, EQL, KQL/Lucene, SPL,
  ES|QL, MQL. ~250 field mappings. 110 unit tests. 12,031 rules / 93 % with
  observables. Earlier shipping but the primary technical moat.

---

## Now — harden the pipeline (the actual moat)

The user-facing UI is in good shape. The REAL moat — the
parse-→-normalize-→-extract-→-store pipeline that turns 8 vendor
formats into one searchable schema — has uneven test coverage. Each
of these items locks in correctness so future refactors can't break
a vendor silently. The site is the storefront; this code is the
inventory.

Sequencing: 1 + 2 + 3 done. 4 + 5 are pure backend hygiene (no
user-facing change). 6 is the first new user-facing signal in a while
and leverages the pipeline depth — start there after 5 if a bigger
deliverable is wanted.

- [x] **1. Per-normalizer tests** — All 8 vendor normalizers
  (`sigma` 18, `elastic` 15, `splunk` 11, `sentinel` 10, `sublime` 9,
  `elastic_protections` 8, `elastic_hunting` 9, `lolrmm` 10 — 90
  tests total) each round-trip a real-format `ParsedRule` and pin
  the canonical taxonomy + extracted observables + status/severity
  normalization + vendor-specific quirks (Splunk story-prefix
  preservation, Sentinel KQL-table → m365 mapping, Elastic Hunting
  ES|QL → esql language token, etc.).
- [x] **2. End-to-end ingestion smoke** — `tests/test_services/test_ingestion_e2e.py`.
  Each of the 8 sources has a raw-content fixture that drives the
  full pipeline (`parse → normalize → _to_detection_model → db.add`)
  and asserts on the resulting `Detection` row read back from the DB.
  Pins the cross-layer wiring: canonical taxonomy resolved from raw
  vendor metadata, MITRE pass-through, language detection, source
  URL construction, dates, vendor-specific quirks (Splunk story
  preservation, Sentinel KQL-table mapping, ES|QL → esql, etc.).
  Catches the class of wiring bug that shipped to prod earlier this
  week.
- [x] **3. Rule-discovery regression test** —
  `tests/test_services/test_rule_discovery.py`. Each source has a
  fixture mini-repo with representative file paths + traps in excluded
  dirs / wrong extensions. `discover_rules()` must hit the minimum
  count, return the canonical paths, and exclude the traps. Plus
  cross-cutting checks: unknown sources return empty, missing repo
  paths return empty, every source in `ALL_REPOSITORY_NAMES` has a
  `DISCOVERY_PATTERNS` entry. Catches the silent-coverage-drop class
  of bug (Sentinel `Detections/` and `ASIM/` were missing from
  discovery for weeks before someone noticed).
- [ ] **4. Field extractor edge-case expansion** — 110 tests on a
  1,266-line file is good but uneven; gaps likely in MQL + ES|QL
  (newer parsers). ~1-2 h.
- [ ] **5. Sentinel taxonomy mapping fix** — Phase 2 audit surfaces
  Sentinel as the only source with serious normalization issues:
  50.1% of rules tagged `cross_platform`, 14.2% with
  `taxonomy_platforms == [unknown]`, 83.2% legacy/canonical
  disagreement. Root cause: the canonical resolver maps the most
  common Sentinel data tables (`SecurityAlert`, `SecurityIncident`,
  `BehaviorAnalytics`, `Anomalies`, `ThreatIntelligenceIndicator`)
  to `cross_platform` instead of a specific upstream platform.
  Extend `app/services/taxonomy/mappings/sentinel.yaml` so meta-tables
  map to the platform they describe (Defender alerts → `microsoft_365`,
  Azure AD behaviour → `azure`, etc.), rebuild indexes, re-run Phase 2
  audit to confirm rates drop. ~2 h.
- [ ] **6. Deterministic quality scoring** — Schema already exists
  (`quality_score`, `quality_details` columns sit empty). Five
  dimensions: metadata completeness, detection specificity, MITRE
  mapping quality, documentation quality, query complexity. New
  `services/quality_scorer.py`. Surface as a sortable column on the
  Detections list. **First fundamentally new user-facing signal in
  a while — leverages the moat.** ~3 h.

## Hidden pages — restore when reworked

Pages are temporarily hidden from nav + routes (still on disk + still
have render-smoke tests, just unreachable from the UI). Each is hidden
because the surface needs rework before we re-expose it. Bookmarked
URLs redirect to `/` so users don't 404.

- [ ] **Intel page** (`/intel`) — `IndustryIntel.tsx`. Hidden because
  the Pulse / Threat Pulse / Trending strip layered too many half-baked
  signals on top of a corpus that still has normalization issues
  (Sentinel `cross_platform` etc.). Restore after the normalization
  audit (Phase 2) lands and we know what signals are actually clean
  enough to surface. Restoration plan probably starts from scratch
  rather than re-enabling the existing layout.
- [ ] **Compare page** (`/compare`, `/compare/side-by-side`) —
  `Compare.tsx` + `SideBySide.tsx`. Hidden because cross-vendor
  comparison was conceptually clean but practically limited — users
  filter by technique/keyword/platform and see N source columns, but
  the comparison logic doesn't lean on the extracted observables (the
  real moat) and so it's just a side-by-side rule list. Restore as
  an **observable-level diff** that highlights "Rule A checks
  `process.name` and `parent.process.name`; Rule B only checks
  `process.name`" — leverages what we extract.

Both pages still have vitest render-smokes; tests pass while pages
are hidden, so re-enabling them later is low-risk.

## Later — non-blocking polish

Lower-priority items. Pick from these as fill-in work between flagship pushes.

### Frontend

- [ ] **Decompose remaining god-components** — IndustryIntel done
  (754 → 116 lines). Still oversized: MitreCoverage 730 L,
  RuleDetail 654 L, RuleComparison 605 L, RuleList 549 L,
  RulePreviewModal 521 L, Home 500 L. Pick one per cycle. Same
  pattern as `pages/intel/`: extract sub-components into a folder
  under `components/<page>/` (or `pages/<page>/`), keep page file
  thin.
- [ ] **Grow vitest coverage further** — render smokes exist for
  IndustryIntel, MitreCoverage, DetectionList, Compare. Lower-risk
  pages without smokes: Home, About, Integrations, RuleDetail,
  SideBySide. Add as time permits.

### Backend

- [ ] **More backend test coverage** — search + ingestion done.
  Lower-priority gaps: scheduler, trending routes, export routes,
  repository_sync, git_service. Pick when they next get touched.

### Hygiene

(Nothing currently pending — README screenshot + supported-source list
shipped; rule-count placeholders dropped from the README rather than
filled, since the README is positioned to stay free of drift-prone data.)

---

## Next — two flagship features (weeks 3–6)

Both reuse infrastructure from the foundation pay-down. Pick one to start;
they don't depend on each other.

### A. MITRE coverage-diff snapshot — *"newly covered technique"*

The single most novel signal we could surface. Nobody else publishes
"Splunk just picked up T1651 — Sigma's had it for two years."

Steps:

1. **`mitre_coverage_snapshot` table** — `(date, technique_id, source, rule_count)`.
   Worker writes one row per technique × source × day on the existing nightly
   sync.
2. **`/trending/newly-covered?days=30` endpoint** — diff today vs N days ago.
   Emit two lists: techniques that went from 0 → ≥ 1 catalog-wide, and
   techniques that went from 0 → ≥ 1 *for a specific source*.
3. **UI card** in Threat Pulse: *"Just covered: T1651 — first Splunk rule
   shipped 2026-04-21."*
4. **First-N-days caveat** — snapshot is only as old as the first row.
   Backfill via git-history replay (expensive) or accept blind window and
   gate the feature on a date threshold.

### B. Threat Actors page

The natural counterpart to the MITRE browser. Reuses MITRE STIX data we
already pull in `services/mitre.py`.

Per-actor view:

- Aliases, MITRE ID (e.g. G0016), description from MITRE
- Stat cards: techniques used, % covered, gap count
- "Covered" list with rule counts
- "Gaps" list — techniques the actor uses that we have zero rules for
  (the actually-actionable signal)

Pairs with feature **A**: when a new rule covers a technique an actor uses,
we can surface "G0016 (Volt Typhoon) is now 4 % more covered this month."

API:
- `GET /api/actors` — list with coverage summary
- `GET /api/actors/{group_id}` — single actor + technique breakdown

Frontend: new `/actors` page + actor detail. Reuses the
left-tree/right-detail pattern from `MitreCoverage`.

---

## Later — conditional on the above landing well

Not committed. Listed in rough priority order.

### Search quality — replace `ILIKE '%term%'`

[`services/search.py:306-320`](../backend/app/services/search.py#L306) does
substring match on `raw_content`, which is why "llm" matches anywhere. Plan
documented previously: Postgres `tsvector` + `ts_rank`. Long-tail upgrade:
`pgvector` for semantic search.

Real user pain. Block on getting a Postgres dev environment set up locally
to avoid SQLite/Postgres feature drift.

### Rule Quality Scoring (deterministic)

Schema already exists (`quality_score`, `quality_details` on `Detection`).
Five dimensions: metadata completeness, detection specificity, MITRE
mapping quality, documentation quality, query complexity. **No LLM** — keep
it explainable and re-runnable. New file:
`backend/app/services/quality_scorer.py`.

### Observable-level rule comparison

Foundation already shipped (12 columns of extracted observables per rule).
Enhance the existing comparison page with per-field diff: *"Rule A checks
`CommandLine` and `ParentImage`; Rule B only checks `CommandLine`."*

### Threat-actor alias normalization

Today the Threat Pulse list has duplicates because vendors name the same
group differently:
- Microsoft: `DEV-0537`
- Industry: `Scattered Spider`
- Splunk: `Scattered Lapsus$ Hunters`

Source: MISP galaxy actor list + MITRE Groups. Static YAML map maintained
in `backend/data/threat_aliases.yaml` to start.

### Per-event-ID dictionaries (taxonomy refinement)

Spun out from Issue 2. Refines `event_type` classification for log channels
that span many distinct event types. Highest-impact: Windows Security
Event Code dictionary. See
[`docs/taxonomy.md`](./taxonomy.md) for the current "no inference"
baseline.

### Saved searches & collections

Local-storage saved filter combinations. "Ransomware Detection Pack" style
curated rule sets with shareable URLs.

### Missing search filters (P0 in old roadmap)

File paths, registry keys, network indicators, target resources, source
tables. Schema is there; just the route + UI work. ~1 hour each.

### New rule sources

- **Google SecOps (chronicle/detection-rules)** — YARA-L parser, ~1–2 days
- **Panther (panther-analysis)** — Python + YAML, ~1–2 days

CrowdStrike CQL Hub deferred — HTML scraper, no public git, ethics review
needed.

### Sentinel threat-tag extraction

Sentinel rule tags include bare threat-actor codenames (`Solorigate`,
`NOBELIUM`, `DEV-0537`, `Zinc`) without a prefix. Threat Pulse skips them
today because distinguishing "threat actor" from "framework reference"
(`NIST 800-53 r5`, `CIS AWS Foundations Benchmark`) needs either a pattern
rule (`APT\d+`, `DEV[-]\d+`, `UNC\d+`) or an external enrichment source
(MISP galaxies). Most of the value unlocks once
[threat-actor alias normalization](#threat-actor-alias-normalization) lands.

### Emerging data sources view

Rank the canonical `taxonomy_data_sources` by new-rule volume over a
window — *"Sentinel `OfficeActivity` is trending: 12 new rules in 30 days."*
Surface on Intel page. Same shape as existing trending endpoints; small
addition. Gated on parser date backfill.

### Gap heatmap per threat

Matrix view: *"Which vendor is covering Threat X, which isn't."*

```
                Sigma  Splunk  Elastic  Sentinel
Volt Typhoon      2       47      3        0
Salt Typhoon      0       50      0        0
Scattered Spider  3       27      5        1
```

Gated on threat-actor alias normalization (otherwise fills with duplicates).

### Week-over-week deltas

Once the snapshot table from flagship **A** lands, reuse it for
per-source, per-technique, per-threat deltas. Renders as sparklines in
the Pulse banner and trend arrows on Threat Pulse cards.

---

## Deferred

These are **not bad ideas** — they're premature given the foundation gaps
above. Not on the calendar this quarter.

- **LLM-assisted quality assessment / rule generation / observable
  extraction** — re-evaluate once search is on `tsvector` and dates are
  populated. Current state is too unstable to layer LLM on top.
- **MCP server integration** — gated on the LLM features above + MCP
  ecosystem maturing.
- **Rule translation engine (Sigma → SPL/KQL/EQL)** — pySigma exists;
  reinventing it is not where the value is.
- **SIEM-native exports** (Kibana JSON, Splunk `.conf`, Sentinel ARM) —
  similar story; downstream tooling already does this.
- **Version history** — useful but expensive (storage), and the
  coverage-diff snapshot covers most of the same intel question more
  cheaply.
- **Competitor reactive features** — `mhaggis/security-detections-mcp`
  changelog is not a roadmap input. Build what users ask for, not what
  competitors ship.

---

## How to use this doc

- **One source of truth.** If you find something elsewhere that contradicts
  this, this doc wins. Open a PR to update.
- **The `Now` section is the only commitment.** `Next` is the plan.
  `Later` is the parking lot. `Deferred` is "not this quarter."
- **`Recently shipped` rolls.** When something lands, move it out of the
  active section into a `CHANGELOG.md` entry.
- **Sub-docs only for deep architecture references** —
  [`docs/taxonomy.md`](./taxonomy.md) is the canonical taxonomy spec.
  Roadmap items belong here, not in a parallel doc.
