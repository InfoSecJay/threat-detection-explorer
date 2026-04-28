# Coverage audit

[`scripts/audit_coverage.py`](../scripts/audit_coverage.py) measures the
gap between what's upstream in each of the 8 source repos and what's
in our catalog. Run on demand any time you want to know whether the
ingest pipeline is honest.

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
