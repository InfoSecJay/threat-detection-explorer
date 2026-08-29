"""Round-trip budget for the sidebar/statistics/filter-option endpoints.

These endpoints run on every catalog page view; on a hosted Postgres
each query is a network round trip, so the number of queries matters
more than their individual cost at ~12k rows. The tests pin the budget
and check that collapsing the queries did not change the answers.
"""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.search import SearchFilters, SearchService


def _make(id_: str, source: str, severity: str, status: str, quality: int | None, **cols) -> Detection:
    return Detection(
        id=id_,
        source=source,
        source_file=f"{source}/{id_}.yml",
        source_repo_url=f"https://example.test/{source}",
        title=id_,
        description="",
        severity=severity,
        status=status,
        language="sigma",
        detection_logic="placeholder",
        raw_content="placeholder",
        quality_score=quality,
        mitre_tactics=cols.get("mitre_tactics", []),
        mitre_techniques=cols.get("mitre_techniques", []),
        tags=[],
        platforms=cols.get("platforms", []),
        event_types=[],
        data_sources=cols.get("data_sources", []),
        extracted_event_ids=[],
        extracted_process_names=cols.get("process_names", []),
        extracted_api_actions=[],
        is_building_block=cols.get("bb", False),
    )


@pytest.fixture
async def corpus(db_session):
    rows = [
        _make("a", "sigma", "high", "stable", 90, platforms=["windows"], mitre_techniques=["T1059"], process_names=["powershell.exe"]),
        _make("b", "sigma", "critical", "experimental", 70, platforms=["windows", "linux"], mitre_techniques=["T1059", "T1003"]),
        _make("c", "elastic", "low", "stable", 50, platforms=["linux"], bb=True),
        _make("d", "splunk", "high", "deprecated", None, platforms=["windows"], process_names=["powershell.exe", "cmd.exe"]),
    ]
    db_session.add_all(rows)
    await db_session.commit()
    return rows


class _Counter:
    """Wrap AsyncSession.execute to count round trips."""

    def __init__(self, db):
        self.db = db
        self.n = 0
        self._orig = db.execute

    async def execute(self, *a, **kw):
        self.n += 1
        return await self._orig(*a, **kw)

    def __enter__(self):
        self.db.execute = self.execute
        return self

    def __exit__(self, *exc):
        self.db.execute = self._orig


def _fm(facet):
    return {f["value"]: f["count"] for f in facet}


@pytest.mark.asyncio
async def test_facets_unfiltered_is_one_query(db_session, corpus):
    search = SearchService(db_session)
    with _Counter(db_session) as c:
        facets = await search.get_facets(SearchFilters())
    assert c.n == 1, f"unfiltered facets should be a single scan, ran {c.n}"
    assert _fm(facets["sources"]) == {"sigma": 2, "elastic": 1, "splunk": 1}
    assert _fm(facets["severities"]) == {"high": 2, "critical": 1, "low": 1}
    assert _fm(facets["platforms"]) == {"windows": 3, "linux": 2}
    assert _fm(facets["mitre_techniques"]) == {"T1059": 2, "T1003": 1}
    assert _fm(facets["process_names"]) == {"powershell.exe": 2, "cmd.exe": 1}
    assert _fm(facets["building_block"]) == {"true": 1}
    assert _fm(facets["quality_band"]) == {"80": 1, "60": 2, "40": 3}


@pytest.mark.asyncio
async def test_facets_each_selected_dimension_adds_one_query(db_session, corpus):
    search = SearchService(db_session)
    with _Counter(db_session) as c:
        facets = await search.get_facets(SearchFilters(sources=["sigma"], severities=["high"]))
    assert c.n == 3, f"two selected dimensions -> shared scan + one each, ran {c.n}"
    # Own-selection exclusion still holds per dimension.
    assert _fm(facets["sources"]) == {"sigma": 1, "splunk": 1}  # severity=high, any source
    assert _fm(facets["severities"]) == {"high": 1, "critical": 1}  # source=sigma, any severity
    assert _fm(facets["platforms"]) == {"windows": 1}  # both applied
    assert _fm(facets["quality_band"]) == {"80": 1, "60": 1, "40": 1}


@pytest.mark.asyncio
async def test_statistics_is_four_queries_and_zero_fills(db_session, corpus):
    search = SearchService(db_session)
    with _Counter(db_session) as c:
        stats = await search.get_statistics()
    assert c.n == 4, f"statistics should be 3 GROUP BYs + hygiene, ran {c.n}"
    assert stats["total"] == 4
    assert stats["by_source"]["sigma"] == 2 and stats["by_source"]["sentinel"] == 0
    assert stats["by_severity"] == {"low": 1, "medium": 0, "high": 2, "critical": 1, "unknown": 0}
    assert stats["by_status"] == {"stable": 2, "experimental": 1, "deprecated": 1, "unknown": 0}
    assert stats["quality_by_source"]["sigma"] == {"avg": 80.0, "scored": 2}
    assert "splunk" not in stats["quality_by_source"]
    assert stats["quality_avg"] == 70.0


@pytest.mark.asyncio
async def test_filter_options_is_one_query_and_matches_per_column_facets(db_session, corpus):
    search = SearchService(db_session)
    with _Counter(db_session) as c:
        opts = await search.get_filter_options()
    assert c.n == 1
    assert opts["sources"] == ["elastic", "sigma", "splunk"]
    assert opts["statuses"] == ["deprecated", "experimental", "stable"]
    assert opts["severities"] == ["critical", "high", "low"]
    assert opts["languages"] == ["sigma"]
    assert opts["platforms"] == await search.get_taxonomy_facet("platforms")
    assert opts["mitre_groups"] == []
    assert set(opts) == {
        "sources", "statuses", "severities", "languages",
        "platforms", "data_sources", "event_types", "use_cases", "mitre_groups", "mitre_software",
    }
