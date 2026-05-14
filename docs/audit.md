# Pipeline audits

Two scripts, two questions:

- [`scripts/audit_coverage.py`](../scripts/audit_coverage.py) -- *are we
  ingesting everything upstream has?* (Phase 1)
- [`scripts/audit_normalization.py`](../scripts/audit_normalization.py)
  -- *are the rules we ingest classified correctly?* (Phase 2)

Both are read-only, exit 0 always, run any time.

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
