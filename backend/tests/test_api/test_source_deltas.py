"""Tests for per-source net deltas from sync-job history (#19):
service maths + the /api/trending/source-deltas route."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.sync_job import SyncJob
from app.services.source_deltas import compute_source_deltas


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _full_job(completed_at: datetime, counts: dict[str, int], **kw) -> SyncJob:
    results = {
        name: {"sync_success": True, "ingest_success": True, "rules_stored": n}
        for name, n in counts.items()
    }
    results.update(kw.pop("extra_results", {}))
    base = dict(
        job_type="full",
        repository=None,
        triggered_by="scheduled",
        status="completed",
        started_at=completed_at - timedelta(minutes=30),
        completed_at=completed_at,
        repository_results=results,
        created_at=completed_at - timedelta(minutes=30),
    )
    base.update(kw)
    return SyncJob(**base)


T0 = datetime(2026, 8, 29, 6, 0, 0)


@pytest.mark.asyncio
async def test_no_data_without_a_completed_full_job(db_session):
    db_session.add(_full_job(T0, {"sigma": 10}, status="failed"))
    db_session.add(_full_job(T0, {"sigma": 10}, repository="sigma"))  # single-repo job
    await db_session.commit()
    out = await compute_source_deltas(db_session, days=7)
    assert out["method"] == "no_data"
    assert out["by_source"] == {}


@pytest.mark.asyncio
async def test_insufficient_history_reports_current_only(db_session):
    db_session.add_all([
        _full_job(T0, {"sigma": 100, "splunk": 50}),
        _full_job(T0 - timedelta(days=3), {"sigma": 90}),  # too recent for a 7d baseline
    ])
    await db_session.commit()
    out = await compute_source_deltas(db_session, days=7)
    assert out["method"] == "insufficient_history"
    assert out["baseline_job_id"] is None
    assert out["by_source"]["sigma"] == {"current": 100, "baseline": None, "delta": None}
    assert out["by_source"]["splunk"]["delta"] is None


@pytest.mark.asyncio
async def test_delta_uses_newest_job_at_least_days_old(db_session):
    """Baseline = the NEWEST completed job at or before latest - days,
    not the oldest one in the table."""
    db_session.add_all([
        _full_job(T0, {"sigma": 100, "splunk": 50, "okta": 34}),
        _full_job(T0 - timedelta(days=6, hours=23), {"sigma": 99}),   # 6d23h: too recent
        _full_job(T0 - timedelta(days=7), {"sigma": 95, "splunk": 55}),  # exactly 7d: baseline
        _full_job(T0 - timedelta(days=14), {"sigma": 10, "splunk": 10}),  # older, ignored
    ])
    await db_session.commit()
    out = await compute_source_deltas(db_session, days=7)
    assert out["method"] == "sync_jobs"
    assert out["baseline_at"].startswith((T0 - timedelta(days=7)).isoformat()[:19])
    assert out["by_source"]["sigma"] == {"current": 100, "baseline": 95, "delta": 5}
    assert out["by_source"]["splunk"] == {"current": 50, "baseline": 55, "delta": -5}
    # Onboarded inside the window: no baseline, no delta, but current shown.
    assert out["by_source"]["okta"] == {"current": 34, "baseline": None, "delta": None}


@pytest.mark.asyncio
async def test_failed_ingest_and_junk_results_are_skipped(db_session):
    db_session.add_all([
        _full_job(
            T0,
            {"sigma": 100},
            extra_results={
                "splunk": {"sync_success": True, "ingest_success": False, "rules_stored": 0},
                "junk": "not-a-dict",
                "weird": {"ingest_success": True, "rules_stored": "many"},
            },
        ),
        _full_job(T0 - timedelta(days=8), {"sigma": 90, "splunk": 40}),
    ])
    await db_session.commit()
    out = await compute_source_deltas(db_session, days=7)
    assert out["by_source"]["sigma"]["delta"] == 10
    # splunk failed ingest in the latest job -> current unknown, no delta.
    assert out["by_source"]["splunk"] == {"current": None, "baseline": 40, "delta": None}
    assert "junk" not in out["by_source"]
    assert "weird" not in out["by_source"]


@pytest.mark.asyncio
async def test_route_shape_and_validation(client, db_session):
    db_session.add_all([
        _full_job(T0, {"sigma": 100}),
        _full_job(T0 - timedelta(days=7), {"sigma": 97}),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/source-deltas", params={"days": 7})
    assert resp.status_code == 200
    data = resp.json()
    assert data["days"] == 7
    assert data["method"] == "sync_jobs"
    assert data["by_source"]["sigma"]["delta"] == 3
    assert data["current_job_id"] and data["baseline_job_id"]

    assert (await client.get("/api/trending/source-deltas", params={"days": 0})).status_code == 422
    assert (await client.get("/api/trending/source-deltas", params={"days": 91})).status_code == 422
