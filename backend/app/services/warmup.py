"""Background cache warm-up at API start.

Every deploy restarts the API process and empties the in-memory
corpus_cache / actor score bundle, so the first visitor to the
catalog, the actors list or a popular actor page paid the cold cost
(0.8s sidebar, 2-4s actor detail). This task rebuilds the hot entries
right after startup, sequentially on one session so it never crowds
out real requests. Everything is best-effort: a failure is logged and
the next request simply computes on demand.
"""

from __future__ import annotations

import logging
import time

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Actor pages to pre-build, by weighted gap (the ordering the Actors
# page, the Home gap spotlight and the heatmap all lead with).
TOP_ACTORS = 15


async def warm_caches(db: AsyncSession, *, top_actors: int = TOP_ACTORS) -> dict[str, float]:
    """Populate the corpus-derived caches. Returns {step: seconds}."""
    # Imported here so the module is cheap to import from main.py and
    # the route module's heavy imports stay lazy.
    from app.api.routes.actors import get_actor
    from app.api.routes.compare import get_coverage_matrix
    from app.services.actor_scores import actor_score_service
    from app.services.coverage_heatmap import technique_source_counts
    from app.services.digest import compute_digest
    from app.services.mitre import mitre_service
    from app.services.search import SearchFilters, SearchService

    timings: dict[str, float] = {}

    async def step(name: str, coro) -> None:
        t0 = time.perf_counter()
        try:
            await coro
        except Exception:  # noqa: BLE001 -- best effort, never fatal
            logger.exception("cache warm-up step %s failed", name)
        timings[name] = round(time.perf_counter() - t0, 3)

    search = SearchService(db)
    await step("statistics", search.get_statistics())
    await step("filter_options", search.get_filter_options())
    await step("facets", search.get_facets(SearchFilters()))
    await step("technique_source_counts", technique_source_counts(db))
    await step("digest", compute_digest(db))

    await step("mitre", mitre_service.ensure_loaded())
    # Home hero reads the parent-technique matrix; the ATT&CK browser the full one.
    await step("coverage_matrix", get_coverage_matrix(tactic=None, include_subtechniques=False, db=db))
    await step("coverage_matrix_sub", get_coverage_matrix(tactic=None, include_subtechniques=True, db=db))
    bundle = None
    try:
        t0 = time.perf_counter()
        bundle = await actor_score_service.get(db)
        timings["actor_scores"] = round(time.perf_counter() - t0, 3)
    except Exception:  # noqa: BLE001
        logger.exception("cache warm-up step actor_scores failed")

    if bundle is not None and top_actors > 0:
        # Two audiences: the gap-ranked actors the site leads with, and
        # the best-covered ones (APT29, APT28, ...) that people search
        # for by name. Union, gap list first.
        by_gap = sorted(bundle.groups.items(), key=lambda kv: -kv[1].weighted_gap)[:top_actors]
        by_rules = sorted(bundle.groups.items(), key=lambda kv: -kv[1].exact_rule_count)[:top_actors]
        seen: set[str] = set()
        for actor_id, _ in [*by_gap, *by_rules]:
            if actor_id in seen:
                continue
            seen.add(actor_id)
            await step(f"actor:{actor_id}", get_actor(actor_id, match_mode="exact", db=db))

    total = round(sum(timings.values()), 3)
    logger.info("cache warm-up done in %.1fs (%d steps)", total, len(timings))
    return timings


async def warm_caches_background() -> None:
    """Entry point for the lifespan task: own session, own error boundary."""
    from app.database import async_session_maker

    try:
        async with async_session_maker() as db:
            await warm_caches(db)
    except Exception:  # noqa: BLE001
        logger.exception("cache warm-up aborted")
