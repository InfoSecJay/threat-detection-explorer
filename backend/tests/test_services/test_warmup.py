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
