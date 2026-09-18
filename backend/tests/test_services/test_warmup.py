"""Startup cache warm-up: populates the corpus caches and never raises."""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.services.search import SearchFilters, SearchService
from app.services.warmup import warm_caches


@pytest.mark.asyncio
async def test_warm_caches_populates_corpus_cache(db_session, monkeypatch):
    db_session.add(Detection(
        id="sigma:1", source="sigma", source_file="a.yml", source_repo_url="https://example.test",
        title="A", description="", severity="high", status="stable", language="sigma",
        detection_logic="x", raw_content="x", mitre_tactics=[], mitre_techniques=["T1059"],
        tags=[], platforms=[], event_types=[], data_sources=[], extracted_event_ids=[],
        extracted_process_names=[], extracted_api_actions=[],
    ))
    await db_session.commit()

    # The actor steps need the ATT&CK catalog; keep the test hermetic by
    # skipping them (top_actors=0) and making ensure_loaded a no-op.
    from app.services.mitre import mitre_service

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)

    timings = await warm_caches(db_session, top_actors=0)
    assert {"statistics", "filter_options", "facets", "technique_source_counts", "digest"} <= set(timings)
    assert corpus_cache.stats()["entries"] >= 5

    # The warmed entries are what the request path reads.
    search = SearchService(db_session)
    before = corpus_cache.hits
    await search.get_statistics()
    await search.get_facets(SearchFilters())
    assert corpus_cache.hits == before + 2


@pytest.mark.asyncio
async def test_warm_caches_survives_a_failing_step(db_session, monkeypatch):
    from app.services import search as search_mod

    async def boom(self):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(search_mod.SearchService, "get_statistics", boom)
    from app.services.mitre import mitre_service

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)

    timings = await warm_caches(db_session, top_actors=0)
    assert "statistics" in timings  # recorded, not raised
    assert "facets" in timings  # later steps still ran


@pytest.mark.asyncio
async def test_warm_caches_passes_every_query_default_explicitly(db_session, monkeypatch):
    """warm_caches calls route functions directly, outside FastAPI's
    dependency injection, so a Query-defaulted parameter left out
    arrives as the fastapi.params.Query object itself. The actor steps
    failed on "'Query' object has no attribute 'split'" and the
    coverage matrix on "Unknown domain: annotation=..." from the day
    the scope selector (#143) and the domain filter (#135) shipped, and
    the best-effort logging hid it: nothing was pre-warmed."""
    import inspect

    from fastapi import params

    from app.api.routes import actors as actors_routes
    from app.api.routes import compare as compare_routes
    from app.services.actor_scores import actor_score_service
    from app.services.mitre import mitre_service

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)

    real = {"get_actor": actors_routes.get_actor, "get_coverage_matrix": compare_routes.get_coverage_matrix}
    calls: dict[str, list[dict]] = {}

    def recorder(name: str):
        async def _stub(*args, **kwargs):
            calls.setdefault(name, []).append(kwargs)
            return {}

        return _stub

    monkeypatch.setattr(actors_routes, "get_actor", recorder("get_actor"))
    monkeypatch.setattr(compare_routes, "get_coverage_matrix", recorder("get_coverage_matrix"))

    class _Score:
        weighted_gap = 1.0
        exact_rule_count = 1

    class _Bundle:
        groups = {"G0016": _Score()}

    async def fake_bundle(db):
        return _Bundle()

    monkeypatch.setattr(actor_score_service, "get", fake_bundle)

    await warm_caches(db_session, top_actors=1)

    for name, fn in real.items():
        query_params = {
            p.name for p in inspect.signature(fn).parameters.values()
            if isinstance(p.default, params.Query)
        }
        assert calls.get(name), f"{name} was never warmed"
        for kwargs in calls[name]:
            missing = query_params - set(kwargs)
            assert not missing, f"{name} warmed without {sorted(missing)}"

