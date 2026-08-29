"""Building-block tri-state filter + facets at the SQL level (issue #26).

Runs against the shared in-memory SQLite `db_session` fixture with a
tiny corpus; the point is that `building_block=True/False/None` and
the `building_block` / `statuses` facet dimensions behave as the API
documents. The NULL-as-False rule for rows that pre-date the column
cannot be exercised here (the ORM schema is NOT NULL); it is pinned at
the clause level in test_status_vocab.py (`IS NOT true`).
"""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.search import SearchFilters, SearchService


def _row(id_: str, *, status: str = "stable", bb: bool = False) -> Detection:
    return Detection(
        id=id_,
        source="elastic",
        source_file=f"elastic/{id_}.toml",
        source_repo_url="https://example.test/elastic",
        title=f"Rule {id_}",
        description="",
        severity="medium",
        status=status,
        language="eql",
        detection_logic="placeholder",
        raw_content="placeholder",
        is_building_block=bb,
    )


@pytest.fixture
async def search(db_session):
    db_session.add_all(
        [
            _row("bb1", bb=True),
            _row("bb2", bb=True, status="test"),
            _row("r1"),
            _row("r2", status="test"),
            _row("legacy"),
        ]
    )
    await db_session.commit()
    return SearchService(db_session)


@pytest.mark.asyncio
async def test_tri_state_filter(search):
    only, n_only = await search.search_detections(SearchFilters(building_block=True))
    assert n_only == 2 and {r.id for r in only} == {"bb1", "bb2"}
    hide, n_hide = await search.search_detections(SearchFilters(building_block=False))
    assert n_hide == 3 and {r.id for r in hide} == {"r1", "r2", "legacy"}
    both, n_both = await search.search_detections(SearchFilters())
    assert n_both == 5


@pytest.mark.asyncio
async def test_facets_report_building_block_true_bucket_and_statuses(search):
    facets = await search.get_facets(SearchFilters())
    assert facets["building_block"] == [{"value": "true", "count": 2}]
    assert {(o["value"], o["count"]) for o in facets["statuses"]} == {("stable", 3), ("test", 2)}


@pytest.mark.asyncio
async def test_building_block_facet_ignores_its_own_selection(search):
    # Selecting "hide building blocks" must not zero the count the
    # sidebar shows for the "only" option.
    facets = await search.get_facets(SearchFilters(building_block=False))
    assert facets["building_block"] == [{"value": "true", "count": 2}]
    facets = await search.get_facets(SearchFilters(statuses=["test"]))
    assert facets["building_block"] == [{"value": "true", "count": 1}]


@pytest.mark.asyncio
async def test_status_filter_uses_new_vocabulary(search):
    rows, total = await search.search_detections(SearchFilters(statuses=["test"]))
    assert total == 2 and {r.id for r in rows} == {"bb2", "r2"}
