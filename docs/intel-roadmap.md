# Detection Intelligence Roadmap

The Intel page exists to answer one question: **what is the detection-engineering
industry working on right now?** This doc captures what we have today and the
prioritized path to make the answer sharper.

## Today

| Signal | Source | Notes |
| --- | --- | --- |
| Detection Pulse (volume) | `/trending/summary` | Rule count + per-source breakdown in window. Biased — see [date-extraction gap](#p0-parser-date-extraction) below. |
| Named threats | `/trending/threats` | Extracted from Splunk `analytic_story` + Sublime `Malfam:` tags. 100% dynamic — no hardcoded threat names. |
| CVE watch | `/trending/threats` (CVEs) | Regex `CVE-\d{4}-\d{4,7}` over tags + title + description across every source. |
| Upstream releases | `/releases/*` | Hero feed of sigma / splunk / elastic GitHub releases. |
| Notable new rules | `/trending/recent-rules` | Richer cards (source · severity · platform tags · date), deduped across created + modified. |
| Trending techniques + platforms | `/trending/techniques`, `/trending/platforms` | Filterable by source / platform / event type. |

## P0 — Parser date extraction

The whole page is subtly wrong until this is fixed.

Only Elastic (1524/1524) and Sigma (2426/3692) have `rule_modified_date`
populated. Splunk, Sentinel, Sublime, Elastic Protections, and Elastic Hunting
all ingest with **null modified dates**, so anything filtered by a time window
(`/trending/techniques`, `/trending/platforms`, `/trending/recent-rules`,
`/trending/summary`) silently excludes 60 %+ of the corpus. The threat-pulse
endpoint already works around this by scanning the full catalog.

**Task:** audit each parser's handling of modified/created dates. Known fields:

- **Splunk** — `date` is often present in the YAML (`data.get("date")`); extract into `rule_created_date`. Splunk doesn't carry a modified date — fall back to repo commit date when we sync.
- **Sentinel** — ARM template YAML doesn't have a `date` field. Use the repo-file git history from the sync worker.
- **Sublime** — check for `created_at` / `modified_at` in the rule YAML.
- **Elastic Protections / Hunting** — TOML `metadata` section may include `updated_date`.

Once backfilled, remove the full-catalog scan in `/trending/threats` and add a
`days` parameter back in. Velocity metrics (rule-count deltas, source
activity) start being honest.

## P1 — Newly covered techniques (coverage diff)

The request: *"what is a new technique in new rules, that we didn't have before?"*

Needs infrastructure:

1. **`mitre_coverage_snapshot` table** — daily worker writes `(date, technique_id,
   source, rule_count)` rows. One row per technique × source × day.
2. **`/trending/newly-covered?days=30`** — compare today's coverage to N days
   ago. Emit techniques whose aggregate count went from 0 → ≥ 1, and
   separately techniques whose per-source count went from 0 → ≥ 1 (so we can
   say "Splunk just picked up T1651 — Sigma's had it for 2 years").
3. **UI** — new card in Threat Pulse: "Just covered: T1651 Cloud Administration
   Command — first Splunk rule shipped 2026-04-21."

Payoff is high — this is genuinely novel signal vs. all the existing "top N"
views. Work is concentrated in the snapshot table + cron + one diff query.

Caveat: the snapshot table is only as old as the first backfill. Either
backfill by replaying git history of each source repo (expensive) or accept
that the first N days of data are blind and mark the feature "available after
YYYY-MM-DD."

## P1 — Splunk normalizer fix

`backend/app/normalizers/splunk.py` strips `story:` / `asset:` / `domain:`
prefixes from every tag ([splunk.py:178-184](../backend/app/normalizers/splunk.py#L178-L184)).
The threat-pulse endpoint works around this with source-aware extraction, but
fixing the root cause is cheaper long-term:

- Keep the prefix for `story:` (high-signal, unique to Splunk).
- Drop the asset/domain noise entirely — those tags repeat the taxonomy columns
  we already compute.

Low risk, one-file change, requires a full Splunk re-ingest to take effect.

## P2 — Threat-name normalization across vendors

Today the Threat Pulse list has duplicates because vendors use different names
for the same actor:

- Microsoft tracking code: `DEV-0537` (Sentinel tag)
- Industry name: `Scattered Spider` / `Scattered Lapsus$ Hunters` (Splunk story)
- CISA advisory: `CISA AA23-347A` (same group's activity)

A normalization layer would merge these into one `ThreatActor` entry with
aliases, and let the card show all three sources contributing to a single row.

Approach:

1. Start with a static YAML map maintained in-repo (`backend/data/threat_aliases.yaml`).
2. Enrich from MISP Galaxies and MITRE Groups (both publish alias lists as JSON).
3. Long-run: auto-suggest merges via embedding similarity of threat names across vendors.

## P2 — Sentinel threat-tag extraction

Sentinel tags include bare threat-actor codenames (`Solorigate`, `NOBELIUM`,
`DEV-0537`, `Zinc`) without a distinguishing prefix. We skip them today because
distinguishing "threat actor" from "framework reference" (`NIST 800-53 r5`,
`CIS AWS Foundations Benchmark`) would need an allowlist — exactly the hardcoding
we're trying to avoid.

**Options:**

- **Pattern-based** — match `APT\d+`, `DEV[-]\d+`, `UNC\d+`, `Dev-\d+` dynamically. Catches Microsoft's codename schema without naming specific groups.
- **Denylist** — enumerate the framework/compliance tags explicitly, treat everything else as a threat candidate. More false positives than the pattern approach.
- **External enrichment** — cross-check against MISP galaxy actor names (comes with aliases for free).

## P2 — Emerging data sources

The taxonomy already computes `taxonomy_data_sources` per rule. A ranked view
of *"which data sources are getting the most new coverage"* surfaces shifts in
detection attention (e.g., "Sentinel OfficeActivity is trending — 12 new rules
in the last 30 days"). Depends on [P0 — date extraction](#p0-parser-date-extraction).

Same shape as existing trending endpoints — small addition.

## P3 — Week-over-week deltas

Once the snapshot table from [P1](#p1--newly-covered-techniques-coverage-diff) is landed,
re-use it to compute week-over-week deltas on:

- Total rule volume per source
- Top techniques (who's climbing, who's dropping)
- Threat mentions

Render as sparklines in the Pulse banner and per-card trend arrows on the
Threat Pulse. Needs a `period_compare` query param on the summary endpoint.

## P3 — Gap heatmap per threat

Expose *"which vendor is covering Threat X and which isn't"* as a heatmap:

```
                Sigma  Splunk  Elastic  Sentinel
Volt Typhoon      2       47      3        0
Salt Typhoon      0       50      0        0
Scattered Spider  3       27      5        1
```

High value for detection engineers planning where to write next. Requires
[threat normalization](#p2--threat-name-normalization-across-vendors) first or
the matrix fills with duplicate rows.

## P3 — LLM-authored pulse prose

Weekly summary paragraph at the top of the page, regenerated on a cron:

> *This week, detection engineers focused on cloud identity — 38 new Sigma rules
> cover post-breach persistence in Entra ID. Splunk ESCU shipped 4 detections
> tied to Scattered Spider activity. CVE-2025-59287 crossed a coverage
> threshold with rules from Sigma, Splunk, and Elastic Protections in the same
> week.*

Input: the structured output we already compute (threat pulse, upstream
releases, notable new rules). Prompt a small model with strict formatting
rules. Cheap to run weekly, zero data bias because the prompt just summarizes
pre-computed facts.

## Non-goals

- **Scoring rule quality.** We have a `quality_score` column, but surfacing it
  on the Intel page turns it from "what is the industry watching" into "what
  is the industry doing well," which is a different page.
- **Alerting.** Intel is retrospective. Real-time pushes (Slack webhooks,
  RSS) would be an out-of-scope notification product.
- **Enrichment from paid TI feeds.** MISP galaxies and MITRE/CISA are enough
  to cover 90 % of named threats.

## Sequencing recommendation

1. **Now** — page is shipped, threat pulse is live from vendor tags with the tightened denylist.
2. **Next (small)** — P0 parser date extraction. Unblocks every time-windowed metric.
3. **Next (medium)** — P1 coverage-diff snapshot. Single biggest net-new signal.
4. **Later** — P2 threat normalization + Sentinel extraction together (they share a codebase and a data source).
5. **Eventually** — P3 deltas, heatmap, prose.
