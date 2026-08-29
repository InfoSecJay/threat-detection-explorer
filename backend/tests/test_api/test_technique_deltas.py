"""Technique-level deltas from coverage snapshots (#19)."""

from __future__ import annotations

from datetime import date

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.services.technique_deltas import compute_technique_deltas


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _snap(day: date, technique: str, source: str, count: int) -> MitreCoverageSnapshot:
    return MitreCoverageSnapshot(snapshot_date=day, technique_id=technique, source=source, rule_count=count)


TODAY = date(2026, 8, 29)


@pytest.mark.asyncio
async def test_no_data_and_insufficient_history(db_session):
    assert (await compute_technique_deltas(db_session))["method"] == "no_data"
    db_session.add(_snap(TODAY, "T1059", "sigma", 5))
    db_session.add(_snap(date(2026, 8, 25), "T1059", "sigma", 4))  # only 4 days old
    await db_session.commit()
    out = await compute_technique_deltas(db_session, days=7)
    assert out["method"] == "insufficient_history"
    assert out["current_date"] == "2026-08-29"


@pytest.mark.asyncio
async def test_gainers_losers_and_source_changes(db_session):
    db_session.add_all([
        # baseline: exactly 7 days old (newest on/before cutoff wins over the 14d one)
        _snap(date(2026, 8, 22), "T1059", "sigma", 10),
        _snap(date(2026, 8, 22), "T1059", "splunk", 5),
        _snap(date(2026, 8, 22), "T1003", "sigma", 8),
        _snap(date(2026, 8, 22), "T1566", "elastic", 3),
        _snap(date(2026, 8, 15), "T1059", "sigma", 1),
        # current
        _snap(TODAY, "T1059", "sigma", 12),
        _snap(TODAY, "T1059", "splunk", 5),
        _snap(TODAY, "T1059", "elastic", 2),   # elastic newly covers T1059
        _snap(TODAY, "T1003", "sigma", 6),     # dropped 2
        _snap(TODAY, "T1078", "sigma", 4),     # brand new technique
        # T1566 vanished entirely (elastic dropped it)
    ])
    await db_session.commit()

    out = await compute_technique_deltas(db_session, days=7, limit=10)
    assert out["method"] == "snapshot"
    assert out["baseline_date"] == "2026-08-22"
    gainers = {g["technique_id"]: g for g in out["gainers"]}
    losers = {l["technique_id"]: l for l in out["losers"]}

    assert [g["technique_id"] for g in out["gainers"]] == ["T1059", "T1078"]
    assert gainers["T1059"] == {
        "technique_id": "T1059", "current": 19, "baseline": 15, "delta": 4,
        "sources_added": ["elastic"], "sources_removed": [],
    }
    assert gainers["T1078"]["baseline"] == 0 and gainers["T1078"]["sources_added"] == ["sigma"]
    assert [l["technique_id"] for l in out["losers"]] == ["T1566", "T1003"]
    assert losers["T1566"]["sources_removed"] == ["elastic"] and losers["T1566"]["current"] == 0


@pytest.mark.asyncio
async def test_route_limit_and_validation(client, db_session):
    db_session.add_all([
        _snap(date(2026, 8, 20), "T1059", "sigma", 1),
        _snap(TODAY, "T1059", "sigma", 3),
        _snap(TODAY, "T1003", "sigma", 3),
    ])
    await db_session.commit()
    resp = await client.get("/api/trending/technique-deltas", params={"days": 7, "limit": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "snapshot"
    assert len(data["gainers"]) == 1
    assert (await client.get("/api/trending/technique-deltas", params={"days": 0})).status_code == 422
    assert (await client.get("/api/trending/technique-deltas", params={"limit": 51})).status_code == 422
