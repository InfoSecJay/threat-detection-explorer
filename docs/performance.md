# Performance notes

How the read path stays fast on a hosted Postgres where every query is
a network round trip, and what to keep in mind when adding endpoints.
Numbers are from production on 2026-08-29 (~12k rules).

## The shape of the problem

The corpus changes only when the sync worker commits (nightly, plus
manual triggers). Almost every page, however, needs an aggregate over
the whole table: sidebar facet counts, statistics, filter options,
technique -> source coverage, actor rule matching. Recomputing those on
every request meant 14-22 round trips or a full scan per page view.

## Three layers

1. **Fewer round trips.** `SearchService.get_facets` groups sidebar
   dimensions by their effective filter set and fetches every needed
   column in one scan per group (unfiltered sidebar: 14 queries -> 1;
   each selected dimension adds one). `get_statistics` is three
   GROUP BYs instead of one COUNT per vocabulary value.
   `get_filter_options` is one scan instead of ten.
   Pinned by `tests/test_services/test_search_round_trips.py`.

2. **Corpus-fingerprint memo** (`app/services/corpus_cache.py`).
   Computed payloads are keyed on `(COUNT(*), MAX(updated_at))` -- the
   same stamp the actor score bundle uses -- so a warm hit costs one
   tiny query and any ingest (new, changed or removed rows)
   invalidates everything at once. The API and worker are separate
   processes; the API sees the worker's commit through the fingerprint
   on its next request, no signalling needed. Entries are bounded
   (512, LRU) because free-text facet queries would otherwise grow the
   cache without bound. Memoised today: facets (per filter set),
   statistics, filter options, the technique -> source map (shared by
   the heatmap and every actor page), actor detail (per actor, match
   mode and catalog version), the digest (per UTC day).

3. **Warm-up at startup** (`app/services/warmup.py`). A deploy empties
   the in-memory caches, so the lifespan starts a background task that
   rebuilds the hot entries plus the 15 largest-gap and 15 best-covered actor pages. Best
   effort; `WARM_CACHES_ON_START=false` disables it.

## Measured effect (production, warm)

| Endpoint | Before | After |
|---|---|---|
| `GET /detections/facets` (unfiltered) | 1.85 s | 0.20 s |
| `GET /detections/filters` | 1.04 s | 0.12 s |
| `GET /detections/statistics` | 0.23 s | 0.12 s |
| `GET /actors/{id}` | 2.5-2.9 s | 0.13 s |
| `GET /digest` | 0.52 s | 0.10 s |

Cold (first-after-deploy) costs are unchanged; the warm-up exists so
a visitor rarely sees them.

Frontend: the rule detail chunk dropped from 641 KB to 73 KB by using
the light Prism build with only the five grammars we render
(`components/ruledetail/CodeBlock.tsx`).

## Adding an endpoint

- If it aggregates over the corpus and takes no user-specific input,
  wrap the computation in `corpus_cache.get(db, key, compute)`. Put
  anything else that changes the answer (catalog version, UTC date)
  in the key.
- If it scans JSON list columns, aggregate in Python from one
  `select(col1, col2, ...)` rather than one query per dimension.
  Portable across SQLite (dev/tests) and Postgres (prod).
- Count queries in a test with the `_Counter` pattern from
  `test_search_round_trips.py`; the budget is the contract.
- Do not cache anything keyed on unbounded user input without the LRU
  bound, and never cache across users if auth ever lands.
