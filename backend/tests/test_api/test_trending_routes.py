"""Tests for /api/trending/weekly-activity and /summary (#24).

The routes bucket in Python from (source, date) rows so they behave the
same on SQLite and Postgres; these tests pin the bucketing maths with
`utcnow` frozen to a known Wednesday.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import trending as trending_routes
from app.database import get_db
from app.main import app
from app.models.detection import Detection

# Wednesday 2026-08-26 15:00 UTC -> current ISO week starts Mon 2026-08-24.
FROZEN_NOW = datetime(2026, 8, 26, 15, 0, 0)


@pytest.fixture
async def client(db_session, monkeypatch):
    monkeypatch.setattr(trending_routes, "utcnow", lambda: FROZEN_NOW)

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(**kw) -> Detection:
    base = dict(
        source="sigma",
        source_file="rules/test.yml",
        source_repo_url="https://example.com/repo",
        title="Test rule",
        detection_logic="selection: x",
        language="sigma",
        raw_content="raw",
    )
    base.update(kw)
    return Detection(**base)


# -- /weekly-activity ---------------------------------------------------


@pytest.mark.asyncio
async def test_weekly_activity_buckets_by_iso_week(client, db_session):
    """weeks=4 -> Mon Aug 3 / 10 / 17 / 24. Boundaries are inclusive at
    the bucket start and the day before the oldest bucket is dropped."""
    db_session.add_all([
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 3, 0, 0, 0)),     # idx 0, first second
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 9, 23, 59, 59)),  # idx 0, last second
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 10, 0, 0, 0)),    # idx 1
        _rule(source="splunk", rule_created_date=datetime(2026, 8, 26, 12, 0, 0)),  # idx 3 (this week)
        _rule(source="splunk", rule_created_date=datetime(2026, 8, 2, 23, 59, 59)), # before window
        _rule(source="elastic", rule_modified_date=datetime(2026, 8, 25)),          # modified only: ignored
        _rule(source="not-a-source", rule_created_date=datetime(2026, 8, 25)),      # unknown source: ignored
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/weekly-activity", params={"weeks": 4})
    assert resp.status_code == 200
    data = resp.json()
    assert data["weeks"] == 4
    assert data["week_starts"] == ["2026-08-03", "2026-08-10", "2026-08-17", "2026-08-24"]
    assert data["by_source"]["sigma"] == [2, 1, 0, 0]
    assert data["by_source"]["splunk"] == [0, 0, 0, 1]
    # Zero-activity sources are omitted, unknown sources never appear.
    assert "elastic" not in data["by_source"]
    assert "not-a-source" not in data["by_source"]


@pytest.mark.asyncio
async def test_weekly_activity_validates_weeks_range(client):
    assert (await client.get("/api/trending/weekly-activity", params={"weeks": 3})).status_code == 422
    assert (await client.get("/api/trending/weekly-activity", params={"weeks": 53})).status_code == 422


# -- /summary -----------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_splits_created_from_modified(client, db_session):
    """days=30 from the frozen now -> cutoff 2026-07-27T15:00. A hygiene
    pass (modified only) must not inflate `created`."""
    db_session.add_all([
        _rule(source="sigma",
              rule_created_date=datetime(2026, 8, 20), rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="sigma",
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 25)),
        _rule(source="splunk",
              rule_created_date=datetime(2026, 7, 27, 15, 0, 0)),  # exactly at cutoff: counted
        _rule(source="splunk",
              rule_created_date=datetime(2026, 7, 27, 14, 59, 59)),  # one second too old
        _rule(source="elastic",
              rule_created_date=datetime(2024, 1, 1), rule_modified_date=datetime(2024, 1, 2)),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/summary", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    assert data["cutoff_date"].startswith("2026-07-27T15:00:00")
    assert data["total_created"] == 2
    assert data["total_modified"] == 2
    assert data["by_source"] == {
        "sigma": {"created": 1, "modified": 2},
        "splunk": {"created": 1, "modified": 0},
    }
    assert "elastic" not in data["by_source"]


@pytest.mark.asyncio
async def test_summary_is_empty_on_quiet_corpus(client, db_session):
    db_session.add(_rule(rule_created_date=datetime(2020, 1, 1)))
    await db_session.commit()
    resp = await client.get("/api/trending/summary", params={"days": 7})
    assert resp.status_code == 200
    assert resp.json()["total_created"] == 0
    assert resp.json()["by_source"] == {}
