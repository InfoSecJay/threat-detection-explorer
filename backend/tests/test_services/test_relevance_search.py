"""Weighted full-text search + relevance sort (#12 / teardown F13, S4.13)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects import postgresql

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.query_parser import free_text_terms, parse_query


class TestDialectAwareParsing:
    def test_postgres_bare_word_compiles_to_websearch_tsquery(self):
        clause = parse_query("ransomware", dialect="postgresql")
        sql = str(clause.compile(dialect=postgresql.dialect()))
        assert "search_vector" in sql and "websearch_to_tsquery" in sql
        assert "ilike" not in sql.lower()

    def test_generic_bare_word_keeps_ilike(self):
        clause = parse_query("ransomware", dialect="generic")
        sql = str(clause.compile())
        assert "search_vector" not in sql
        assert "lower(" in sql.lower() or "like" in sql.lower()

    def test_fielded_clauses_unaffected_by_dialect(self):
        clause = parse_query("source:sigma", dialect="postgresql")
        sql = str(clause.compile(dialect=postgresql.dialect()))
        assert "websearch_to_tsquery" not in sql


class TestFreeTextTerms:
    def test_extracts_bare_words_and_phrases_only(self):
        assert free_text_terms('powershell source:sigma "encoded command"') == [
            "powershell", "encoded command",
        ]

    def test_negated_and_fielded_terms_excluded(self):
        assert free_text_terms("-noise title:foo persistence") == ["persistence"]

    def test_garbage_and_empty_are_safe(self):
        assert free_text_terms("") == []
        assert free_text_terms("AND OR ((((") == []


@pytest.fixture
async def client(db_session):
    base = dict(
        source="sigma", source_file="r.yml", source_repo_url="https://x",
        detection_logic="x", language="sigma", raw_content="raw", status="stable",
    )
    db_session.add_all([
        Detection(id="a", title="Old but excellent", severity="high", quality_score=90, **base),
        Detection(id="b", title="New but bare", severity="low", quality_score=20, **base),
        Detection(id="c", title="Middling", severity="medium", quality_score=55, **base),
    ])
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_relevance_without_query_fronts_best_documented(client):
    """S4.13: the catalog default is a curated order (completeness desc,
    newest tiebreak), not whichever source pushed most recently."""
    r = await client.get("/api/detections?sort_by=relevance&limit=10")
    assert r.status_code == 200
    items = r.json()["items"] if "items" in r.json() else r.json()["detections"]
    scores = [i["quality_score"] for i in items]
    assert scores == sorted(scores, key=lambda x: -(x or 0))


@pytest.mark.asyncio
async def test_relevance_with_query_still_works_on_sqlite(client):
    # Dev/SQLite has no tsvector; relevance degrades to the curated
    # order while the bare word still filters via ILIKE.
    r = await client.get("/api/detections?q=excellent&sort_by=relevance")
    assert r.status_code == 200
    body = r.json()
    items = body["items"] if "items" in body else body["detections"]
    assert [i["id"] for i in items] == ["a"]
