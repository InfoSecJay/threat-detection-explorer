"""Persisted cache artifacts + unfiltered-count shortcut (#81 / S2.4, S2.5)."""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.corpus_cache import CorpusCache


def _rule(i: int) -> Detection:
    return Detection(
        id=f"r{i}", source="sigma", source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i} with a title", detection_logic="x", language="sigma",
        raw_content="raw", severity="high", status="stable", quality_score=50 + i,
    )


@pytest.mark.asyncio
async def test_persisted_artifact_survives_a_new_process(db_session):
    db_session.add_all([_rule(1), _rule(2)])
    await db_session.commit()

    calls = {"n": 0}

    async def compute():
        calls["n"] += 1
        return {"facets": [1, 2, 3]}

    first = CorpusCache()
    v1 = await first.get(db_session, ("facets", "default"), compute, persist=True)
    assert v1 == {"facets": [1, 2, 3]} and calls["n"] == 1

    # A fresh cache instance = a fresh process after deploy: the value
    # must come back from the artifact table without recomputing.
    second = CorpusCache()
    v2 = await second.get(db_session, ("facets", "default"), compute, persist=True)
    assert v2 == v1
    assert calls["n"] == 1, "artifact table should have served the second process"


@pytest.mark.asyncio
async def test_fingerprint_change_recomputes_and_overwrites(db_session):
    db_session.add(_rule(1))
    await db_session.commit()

    calls = {"n": 0}

    async def compute():
        calls["n"] += 1
        return {"v": calls["n"]}

    c = CorpusCache()
    assert (await c.get(db_session, ("k",), compute, persist=True)) == {"v": 1}

    db_session.add(_rule(2))  # corpus moves
    await db_session.commit()

    fresh = CorpusCache()
    assert (await fresh.get(db_session, ("k",), compute, persist=True)) == {"v": 2}
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_unserializable_values_still_compute_without_persisting(db_session):
    db_session.add(_rule(1))
    await db_session.commit()

    class Odd:  # not JSON-serializable
        pass

    c = CorpusCache()
    v = await c.get(db_session, ("odd",), lambda: _async(Odd()), persist=True)
    assert isinstance(v, Odd)
    # And a fresh process simply recomputes.
    v2 = await CorpusCache().get(db_session, ("odd",), lambda: _async(Odd()), persist=True)
    assert isinstance(v2, Odd)


async def _async(value):
    return value


@pytest.mark.asyncio
async def test_unfiltered_search_count_uses_fingerprint(db_session):
    from app.services.search import SearchFilters
    from app.services.search import SearchService

    db_session.add_all([_rule(i) for i in range(5)])
    await db_session.commit()

    svc = SearchService(db_session)
    detections, total = await svc.search_detections(SearchFilters(limit=3))
    assert total == 5 and len(detections) == 3

    # Filtered path still counts exactly.
    _d, total_sigma = await svc.search_detections(SearchFilters(sources=["sigma"], limit=3))
    assert total_sigma == 5
