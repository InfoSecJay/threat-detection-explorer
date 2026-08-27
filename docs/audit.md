# Pipeline audits

Three scripts, three questions:

- [`scripts/audit_coverage.py`](../scripts/audit_coverage.py) -- *are we
  ingesting everything upstream has?* (Phase 1)
- [`scripts/audit_normalization.py`](../scripts/audit_normalization.py)
  -- *are the rules we ingest classified correctly?* (Phase 2)
- [`scripts/audit_extraction.py`](../scripts/audit_extraction.py) -- *are
  the observables we extract from rule logic real and precise?*
  (issue #6 baseline)

All are read-only, exit 0 always, run any time.

# Coverage audit (Phase 1)

[`scripts/audit_coverage.py`](../scripts/audit_coverage.py) measures the
gap between what's upstream in each of the 8 source repos and what's
in our catalog.

## What it does

For each source:

1. Fresh-clones (or `git pull`s) the upstream repo into the system
   temp dir.
2. Walks the tree by file extension under the directories where rules
   legitimately live.
3. Runs each candidate file through our `parser.parse()` AND
   `normalizer.normalize()` — same code paths the worker uses during
   nightly sync. Mirrors production: passes the **absolute** path to
   `can_parse()`, the **relative** path to `parse()`.
4. Categorises each outcome:

   | Bucket | Meaning |
   | --- | --- |
   | `CAN_PARSE_FALSE` | parser correctly rejected (deprecated dir, test fixture, wrong subtree). |
   | `PARSE_NONE` | parser returned `None` — silent validation failure (usually missing required field). |
   | `PARSE_RAISED` | parser raised an exception (silent crash — typically a bug worth fixing). |
   | `NORMALIZE_RAISED` | parsed OK but normalizer crashed (cross-layer wiring). |
   | `OK` | parsed AND normalized cleanly. |

5. Hits the production API for the live stored count.
6. Prints a per-source report with the delta + sample failures.

Exits 0 always — this is a report, not a gate.

## Usage

```bash
# All 8 sources (slow on first run — full clones)
python scripts/audit_coverage.py

# One source
python scripts/audit_coverage.py --source elastic

# Machine output for piping
python scripts/audit_coverage.py --json

# Skip the production-count API calls (offline / faster)
python scripts/audit_coverage.py --no-production

# Force fresh clones (instead of git pull)
python scripts/audit_coverage.py --fresh
```

## Reading the output

- **`PARSE_RAISED` and `NORMALIZE_RAISED`** are bugs. The legacy `toml`
  package crash (commit `801d358`) was exactly this class — ~70 silent
  failures uncovered by an audit run. Sample paths point at specific
  rules; reproduce locally, fix, re-audit.
- **`PARSE_NONE`** is informational. Common causes: files that match
  the rule extension but aren't rule files (test fixtures, scaffolding,
  templates). The fix is usually adding the directory to the parser's
  excluded path-component set so they're rejected at `can_parse` time
  instead of failing silently at parse.
- **`DELTA (ok - prod)`** = `OK count − production stored count`.
  - `0` → in sync.
  - positive → the upstream has new rules the production sync hasn't
    picked up yet (sync lag — resolves overnight).
  - negative → production has more rules than upstream parses cleanly,
    which usually means stale rows the cleanup step hasn't pruned.
- **`CAN_PARSE_FALSE`** is *expected* — every source has files we
  legitimately exclude (deprecated, test, sample data, etc.).

## When to run

- **After any parser, normalizer, or discovery change** — verify it
  didn't introduce a silent regression.
- **When a user reports a missing rule** — quickest way to tell whether
  it's a parser issue, a discovery issue, or just sync lag.
- **Before changing canonical taxonomy mappings** — eyeballing the
  PARSE_NONE / RAISED counts gives a baseline for the change.

## Limitations

- Walks files matching the source's rule extension under known
  directories. Will NOT surface coverage gaps where upstream introduces
  a new top-level rules directory we haven't taught the script about
  (e.g. how `rules_building_block/` was missed before
  `630588d`). To catch that class, periodically inspect the upstream
  repo layout for unexpected `rules*` siblings.
- The production count is a single number per source — we don't compare
  rule-by-rule against upstream. A negative delta tells us the count is
  off; figuring out *which* rule is missing still requires hunting via
  search.

# Normalization audit (Phase 2)

[`scripts/audit_normalization.py`](../scripts/audit_normalization.py)
verifies the rules we ingest get classified correctly. Coverage (Phase
1) tells us if a rule made it into the catalog; normalization (Phase 2)
tells us if its `taxonomy_platforms` / `taxonomy_data_sources` /
`taxonomy_event_types` / `mitre_techniques` are right.

## What it does

For each source it paginates the public production API and computes:

- Distribution of the three canonical taxonomy fields (top values, count,
  share of source).
- Headline rates: `cross_platform`, `[unknown]`, no-observables,
  no-MITRE, legacy-canonical disagreement.
- Language distribution (sanity check: Splunk should be 100% `spl`,
  Sentinel 100% `kql`, etc.).
- A set of anomaly heuristics that flag a source when a rate crosses a
  threshold:
  - `taxonomy_platforms == ['unknown']` > 5%  → taxonomy mapping gap
  - `cross_platform` > 5%                     → over-broad fallback
  - no extracted observables > 30%            → parser/extractor gap
  - no MITRE > 30% (suppressed for `sublime`) → MITRE mapping gap
  - legacy `platform` disagreement > 10%      → Phase 3 legacy-removal
                                                will surface this
  - language outside the source's expected set

## Usage

```bash
python scripts/audit_normalization.py
python scripts/audit_normalization.py --source sentinel
python scripts/audit_normalization.py --json
python scripts/audit_normalization.py --api http://localhost:8000/api
```

## Current findings (2026-05-13)

Run against production: **5/8 sources clean, 3 with anomalies.**

| Source              | Rules | cross_platform | unknown | Anomalies |
| ---                 | ---:  | ---:           | ---:    | ---:      |
| sigma               | 3748  | 1.7%           | 0.0%    | 0         |
| elastic_protections | 1230  | 0.0%           | 0.0%    | 0         |
| sublime             | 994   | 0.0%           | 0.0%    | 0         |
| lolrmm              | 492   | 0.2%           | 0.0%    | 0         |
| elastic_hunting     | 138   | 0.0%           | 0.0%    | 1         |
| splunk              | 2068  | 2.3%           | 0.4%    | 1         |
| elastic             | 1831  | 1.1%           | 1.0%    | 1         |
| sentinel            | 2091  | 50.1%          | 14.2%   | 3         |

### Open issues to fix

1. **Sentinel cross_platform = 50.1%, unknown = 14.2%** -- the canonical
   resolver maps the most common Sentinel data tables (`SecurityAlert`,
   `SecurityIncident`, `BehaviorAnalytics`, `Anomalies`,
   `ThreatIntelligenceIndicator`) to `cross_platform` instead of a
   specific platform. Likely fix: extend
   `app/services/taxonomy/mappings/sentinel.yaml` so meta-tables map to
   the upstream platform they describe (Defender alerts →
   `microsoft_365`, Azure AD behaviour → `azure`, etc.) and rebuild
   indexes.
2. **Sentinel legacy `platform` disagreement = 83.2%** -- the legacy
   single-value `platform` field is stale for most Sentinel rules.
   Resolves itself when (1) is fixed and Phase 3 removes the legacy
   column.
3. **elastic_hunting: 4 rules with `SQL` language** -- not in the
   expected set. Probably ES|QL rules whose language tag wasn't lowered
   on ingest, or a real `SQL` query type we hadn't seen. Investigate
   sample rows.
4. **elastic legacy disagreement = 17.7%, splunk = 11.0%** -- same class
   as the Sentinel finding, smaller blast radius. Phase 3 work.

## When to run

- Before promoting a canonical-taxonomy change to production -- compare
  before/after rates.
- After ingesting a new source or schema-changing an existing parser.
- Periodically -- normalization drift is silent and won't show up in
  Phase 1.

## Limitations

- Hits the public production API, so it audits what production has *now*,
  not the latest code in `master`. After a deploy, give the worker one
  sync cycle before re-running.
- Heuristic thresholds are tuned for the current ruleset shape; if a
  source's character changes (e.g. Sublime starts mapping MITRE), update
  the thresholds rather than silencing the script.

# Extraction audit (issue #6)

[`scripts/audit_extraction.py`](../scripts/audit_extraction.py) is the
baseline instrument for the extracted-observables redesign (issue #6):
per source, it measures extraction **coverage** (population rates for
the 9 `extracted_*` array surfaces), **schema conformance** (every
observable's `(type, subtype)` pair validated against the canonical
vocabulary pinned in
[`taxonomy/canonical.py`](../backend/app/services/taxonomy/canonical.py)),
**mapping precision** (share of heuristic `*_field` fallback subtypes,
where the extractor recognized only the *domain* of a field, not its
meaning), and **per-surface FP classes** (named shape tripwires:
process names that are paths, event IDs that aren't event IDs, network
indicators that are booleans or free text, ...).

## Usage

```bash
python scripts/audit_extraction.py
python scripts/audit_extraction.py --source splunk
python scripts/audit_extraction.py --json
python scripts/audit_extraction.py --api http://localhost:8000/api
```

## Baseline findings (2026-08-26, production)

**Coverage is not the problem — precision is.** Every source with an
extractor populates observables for 97-100% of rules, but the share of
imprecise fallback classification and the junk rate vary wildly:

| Source              | Rules | Coverage | Observables | `*_field` fallback | Bad `fields_used` | Dominant FP class |
| ---                 | ---:  | ---:     | ---:        | ---:               | ---:              | ---               |
| sigma               | 3783  | 100.0%   | 12465       | 24.1%              | 17                | 22.8% of file_paths are bare extensions (`.bat`, `.7z`) |
| elastic_protections | 1314  | 99.8%    | 12373       | 28.9%              | 0                 | (clean) |
| elastic             | 2069  | 99.9%    | 13250       | 49.4%              | 27                | 36.9% of event_ids are O365 operation names (`ComplianceDLPExchange`) |
| elastic_hunting     | 140   | 97.1%    | 982         | 54.2%              | 25                | osquery SQL fragments leak into fields_used |
| splunk              | 2156  | 99.9%    | 8125        | 60.0%              | **2066**          | multi-field `\| fields` lines stored unsplit (`"dest user process_id FilterName"`) |
| sentinel            | 2351  | 99.4%    | 4565        | 71.0%              | **1675**          | KQL fragments as field names (`"1d)"`, `"RiskScore desc"`); let-expressions leak into source_tables |
| sublime             | 1196  | 99.4%    | 10971       | 74.3%              | **3092**          | leading-dot MQL fields (`.display_text`) parsed as junk; 218 bare `"."` values |
| lolrmm              | 631   | 100.0%   | 892         | 0.2%               | 0                 | 6.4% of file_paths are bare filenames |
| google_secops       | 379   | 0.0%     | 0           | —                  | —                 | no extractor (YARA-L) |
| panther             | 877   | 0.0%     | 0           | —                  | —                 | no extractor (Python bodies) |
| okta                | 34    | 0.0%     | 0           | —                  | —                 | no extractor |
| auth0               | 34    | 100.0%   | 202         | 97.0%              | 24                | flagged `no_extractor` but generic path fires — 97% fallback, worst precision on the site |

Schema conformance: **zero out-of-vocabulary `(type, subtype)` pairs**
across all 15k rules — the vocabulary pinned in `canonical.py` matches
production reality exactly, so any future out-of-vocab hit is real
drift.

### What this means for the rebuild order (issue #6)

1. **splunk** — biggest junk volume (2,066 unsplit field lists) and
   60% fallback share on 8k observables. The real-grammar rebuild
   (`splunk-sdk` search parser) fixes the `| fields`/`| table`
   splitting class wholesale.
2. **sublime** — 74.3% fallback share and 3,092 junk field names from
   one lexical cause: MQL's leading-dot field syntax. Likely the
   cheapest big win.
3. **sentinel** — 71% fallback, KQL fragments in two surfaces; needs
   real KQL tokenization rather than regex.
4. **elastic** — event-ID misrouting (O365 operation names) plus 49.4%
   fallback; the ECS field map is good, the non-ECS integrations
   aren't.
5. **sigma** — best structured source (YAML detection blocks), so its
   noise is small; the extension-as-path class is a routing fix
   (extensions belong in `file/file_extension`, not file_paths).

`elastic_protections` and `lolrmm` are near-clean and shouldn't be
touched until the big four land. `auth0`'s flag should be corrected
(it *does* extract, badly) or its generic extraction suppressed.

### Rebuild progress

**splunk — rebuilt 2026-08-26** (stage-aware SPL tokenizer replacing
flat regexes). Before/after over the 1,983-rule local corpus, same
audit checkers:

| Metric | Before | After |
| --- | ---: | ---: |
| junk fields_used | 1,890 (22.6%) | **0 (0.0%)** |
| fields_used values | 8,371 | 27,730 (by-lists now split) |
| event_ids non-numeric FP | 18 | 0 |
| file_paths no-separator FP | 12 (17.6%) | 0 |
| file_paths extracted | 68 | 299 |
| process_names | 1,132 | 1,149 |
| network_indicators | 512 | 961 (enum metadata now excluded) |
| `*_field` fallback share | 59.7% | 45.0% |

Production columns refresh automatically on the next nightly sync
(every rule is re-normalized on upsert). The remaining fallback share
is a FIELD_TYPE_MAP vocabulary gap, not a parsing gap — tracked for a
later pass.

## Limitations

- FP-class tripwires are shape heuristics — they catch contract
  violations (a path in a name surface), not semantic errors (a wrong
  but well-formed value). Semantic accuracy needs the per-source
  fixture corpora that the rebuild arc (issue #6) builds.
- Same production-API caveat as the other audits: it measures what
  production has now, not `master`.
