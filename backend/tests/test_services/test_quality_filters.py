"""Hygiene-score surfaces (#39): min_quality filter, `quality:` query
field (comparisons / ranges / equality), the quality_band facet, and
per-source averages on statistics."""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.query_parser import QueryParseError, parse_query
from app.services.search import SearchFilters, SearchService


def _sql(clause) -> str:
    return str(clause.compile(compile_kwargs={"literal_binds": True})).lower()


def _rule(id_: str, source: str, score: int | None) -> Detection:
    return Detection(
        id=id_, source=source, source_file=f"{source}/{id_}.yml",
        source_repo_url="https://example.test", title=id_, severity="medium",
        status="stable", language="sigma", detection_logic="x", raw_content="raw",
        quality_score=score,
    )


@pytest.fixture
async def search(db_session):
    db_session.add_all([
        _rule("a90", "sigma", 90),
        _rule("a75", "sigma", 75),
        _rule("a60", "sigma", 60),
        _rule("b40", "splunk", 40),
        _rule("b20", "splunk", 20),
        _rule("c_none", "elastic", None),
    ])
    await db_session.commit()
    return SearchService(db_session)


# -- query parser ----------------------------------------------------------


class TestQualityField:
    def test_gte_and_gt(self):
        assert "quality_score >= 60" in _sql(parse_query("quality:>=60"))
        assert "quality_score > 60" in _sql(parse_query("quality:>60"))

    def test_lte_and_lt_via_aliases(self):
        assert "quality_score <= 40" in _sql(parse_query("hygiene:<=40"))
        assert "quality_score < 40" in _sql(parse_query("score:<40"))

    def test_inclusive_range(self):
        sql = _sql(parse_query("quality:[60 TO 79]"))
        assert "quality_score >= 60" in sql and "quality_score <= 79" in sql
        assert "is not null" in sql

    def test_open_range_star(self):
        sql = _sql(parse_query("quality:[60 TO *]"))
        assert "quality_score >= 60" in sql

    def test_equality(self):
        assert "quality_score = 80" in _sql(parse_query("quality:80"))

    def test_non_number_is_a_parse_error_with_suggestion(self):
        with pytest.raises(QueryParseError) as exc:
            parse_query("quality:high")
        assert "whole number" in str(exc.value)


# -- search service --------------------------------------------------------


@pytest.mark.asyncio
async def test_min_quality_filter_is_inclusive_and_skips_unscored(search):
    rows, total = await search.search_detections(SearchFilters(min_quality=60))
    assert total == 3
    assert {r.id for r in rows} == {"a90", "a75", "a60"}


@pytest.mark.asyncio
async def test_min_quality_composes_with_other_filters(search):
    rows, total = await search.search_detections(SearchFilters(min_quality=30, sources=["splunk"]))
    assert total == 1 and rows[0].id == "b40"


@pytest.mark.asyncio
async def test_quality_query_field_end_to_end(search):
    rows, _ = await search.search_detections(SearchFilters(q="quality:<50"))
    assert {r.id for r in rows} == {"b40", "b20"}


@pytest.mark.asyncio
async def test_quality_band_facet_is_cumulative_and_ignores_own_threshold(search):
    facets = await search.get_facets(SearchFilters(min_quality=80))
    bands = {b["value"]: b["count"] for b in facets["quality_band"]}
    # Own selection excluded: the 60 band still counts the 60-79 rows.
    assert bands == {"80": 1, "60": 3, "40": 4}

    narrowed = await search.get_facets(SearchFilters(sources=["splunk"]))
    assert {b["value"]: b["count"] for b in narrowed["quality_band"]} == {"80": 0, "60": 0, "40": 1}


# -- statistics ------------------------------------------------------------


@pytest.mark.asyncio
async def test_statistics_carry_hygiene_averages(search):
    stats = await search.get_statistics()
    assert stats["quality_by_source"]["sigma"] == {"avg": 75.0, "scored": 3}
    assert stats["quality_by_source"]["splunk"] == {"avg": 30.0, "scored": 2}
    assert "elastic" not in stats["quality_by_source"]  # nothing scored
    assert stats["quality_avg"] == 57.0  # (90+75+60+40+20)/5
