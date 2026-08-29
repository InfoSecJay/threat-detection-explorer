"""Tests for the /api/scheduler routes (#24 coverage gap).

Exercises the real FastAPI app against an in-memory SQLite session via
the get_db override, so response models, ordering, filters, and the
legacy-shape coercion on `warnings` (#46) are all covered end to end.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes.scheduler import _compute_next_run
from app.config import settings
from app.database import get_db
from app.main import app
from app.models.sync_job import SyncJob


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _job(**kw) -> SyncJob:
    base = dict(
        job_type="full",
        repository=None,
        triggered_by="scheduled",
        status="completed",
        started_at=datetime(2026, 8, 29, 6, 0, 0),
        completed_at=datetime(2026, 8, 29, 6, 30, 0),
        duration_seconds=1800.0,
        rules_discovered=10,
        rules_stored=10,
        error_count=0,
        warning_count=0,
        repository_results={"sigma": {"sync_success": True}},
        error_message=None,
        created_at=datetime(2026, 8, 29, 6, 0, 0),
    )
    base.update(kw)
    return SyncJob(**base)


# -- /status -----------------------------------------------------------


class TestComputeNextRun:
    """The API derives the next cron fire time from settings alone; the
    hour/minute are local to sync_schedule_timezone and the result is
    naive UTC (the storage convention)."""

    def test_later_today_when_before_schedule(self, monkeypatch):
        monkeypatch.setattr(settings, "sync_schedule_hour", 2)
        monkeypatch.setattr(settings, "sync_schedule_minute", 0)
        monkeypatch.setattr(settings, "sync_schedule_timezone", "America/Toronto")
        # 05:00 UTC on Aug 30 = 01:00 EDT -> fires 02:00 EDT = 06:00 UTC same day
        got = _compute_next_run(datetime(2026, 8, 30, 5, 0, 0))
        assert got == datetime(2026, 8, 30, 6, 0, 0)
        assert got.tzinfo is None

    def test_tomorrow_when_past_schedule(self, monkeypatch):
        monkeypatch.setattr(settings, "sync_schedule_hour", 2)
        monkeypatch.setattr(settings, "sync_schedule_minute", 0)
        monkeypatch.setattr(settings, "sync_schedule_timezone", "America/Toronto")
        # 12:00 UTC on Aug 29 = 08:00 EDT, already past 02:00 -> next day
        got = _compute_next_run(datetime(2026, 8, 29, 12, 0, 0))
        assert got == datetime(2026, 8, 30, 6, 0, 0)

    def test_dst_offset_is_honoured(self, monkeypatch):
        monkeypatch.setattr(settings, "sync_schedule_hour", 2)
        monkeypatch.setattr(settings, "sync_schedule_minute", 30)
        monkeypatch.setattr(settings, "sync_schedule_timezone", "America/Toronto")
        # January = EST (UTC-5): 02:30 local = 07:30 UTC
        got = _compute_next_run(datetime(2026, 1, 15, 12, 0, 0))
        assert got == datetime(2026, 1, 16, 7, 30, 0)


@pytest.mark.asyncio
async def test_status_reports_config_and_last_scheduled_run(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "enable_scheduler", True)
    monkeypatch.setattr(settings, "sync_schedule_hour", 2)
    monkeypatch.setattr(settings, "sync_schedule_minute", 0)
    monkeypatch.setattr(settings, "sync_schedule_timezone", "America/Toronto")

    db_session.add_all([
        _job(triggered_by="manual", started_at=datetime(2026, 8, 29, 9, 0, 0)),
        _job(triggered_by="scheduled", started_at=datetime(2026, 8, 28, 6, 0, 0)),
        _job(triggered_by="scheduled", started_at=datetime(2026, 8, 29, 6, 0, 0)),
    ])
    await db_session.commit()

    resp = await client.get("/api/scheduler/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["schedule_hour"] == 2
    assert data["schedule_timezone"] == "America/Toronto"
    assert data["next_run_time"] is not None
    # Latest SCHEDULED run, not the later manual one.
    assert data["last_scheduled_run"].startswith("2026-08-29T06:00:00")


@pytest.mark.asyncio
async def test_status_has_no_next_run_when_scheduler_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "enable_scheduler", False)
    resp = await client.get("/api/scheduler/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert resp.json()["next_run_time"] is None


# -- /jobs ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_jobs_are_newest_first_and_limited(client, db_session):
    base = datetime(2026, 8, 1, 0, 0, 0)
    db_session.add_all([
        _job(created_at=base + timedelta(days=i), rules_stored=i) for i in range(5)
    ])
    await db_session.commit()

    resp = await client.get("/api/scheduler/jobs", params={"limit": 3})
    assert resp.status_code == 200
    stored = [j["rules_stored"] for j in resp.json()]
    assert stored == [4, 3, 2]


@pytest.mark.asyncio
async def test_jobs_repository_filter_includes_all_repo_runs(client, db_session):
    """Filtering by repo returns that repo's jobs PLUS whole-corpus
    (repository=NULL) jobs, since those touched the repo too."""
    db_session.add_all([
        _job(repository="sigma", created_at=datetime(2026, 8, 3)),
        _job(repository="splunk", created_at=datetime(2026, 8, 2)),
        _job(repository=None, created_at=datetime(2026, 8, 1)),
    ])
    await db_session.commit()

    resp = await client.get("/api/scheduler/jobs", params={"repository": "sigma"})
    assert resp.status_code == 200
    repos = [j["repository"] for j in resp.json()]
    assert repos == ["sigma", None]


@pytest.mark.asyncio
async def test_jobs_expose_job_level_warnings(client, db_session):
    """#46: a credential failure recorded by the worker is visible via
    the API, and rows from before the column existed (NULL) serialize
    as an empty list instead of 500ing the endpoint."""
    warning = {
        "code": "github_auth_failed",
        "source": "upstream_verifier",
        "message": "GitHub API returned 401 for upstream_verifier; ...",
    }
    db_session.add_all([
        _job(warnings=[warning], created_at=datetime(2026, 8, 2)),
        _job(warnings=None, created_at=datetime(2026, 8, 1)),
    ])
    await db_session.commit()

    resp = await client.get("/api/scheduler/jobs")
    assert resp.status_code == 200
    newest, legacy = resp.json()
    assert newest["warnings"] == [warning]
    assert legacy["warnings"] == []


@pytest.mark.asyncio
async def test_latest_returns_most_recent_completed_job(client, db_session):
    db_session.add_all([
        _job(status="completed", completed_at=datetime(2026, 8, 1), rules_stored=1),
        _job(status="completed", completed_at=datetime(2026, 8, 3), rules_stored=3),
        _job(status="failed", completed_at=datetime(2026, 8, 5), rules_stored=5),
        _job(status="running", completed_at=None, rules_stored=7),
    ])
    await db_session.commit()

    resp = await client.get("/api/scheduler/jobs/latest")
    assert resp.status_code == 200
    assert resp.json()["rules_stored"] == 3


@pytest.mark.asyncio
async def test_latest_is_null_when_nothing_completed(client):
    resp = await client.get("/api/scheduler/jobs/latest")
    assert resp.status_code == 200
    assert resp.json() is None


@pytest.mark.asyncio
async def test_get_job_by_id_and_404(client, db_session):
    job = _job()
    db_session.add(job)
    await db_session.commit()

    ok = await client.get(f"/api/scheduler/jobs/{job.id}")
    assert ok.status_code == 200
    assert ok.json()["id"] == job.id
    assert ok.json()["repository_results"] == {"sigma": {"sync_success": True}}

    missing = await client.get("/api/scheduler/jobs/does-not-exist")
    assert missing.status_code == 404


# -- /trigger ------------------------------------------------------------


@pytest.mark.asyncio
async def test_trigger_creates_pending_row_for_worker(client, db_session):
    resp = await client.post("/api/scheduler/trigger", json={"repository": "sigma"})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]
    assert "sigma" in resp.json()["message"]

    row = await db_session.get(SyncJob, job_id)
    assert row is not None
    assert row.status == "pending"
    assert row.job_type == "full"
    assert row.repository == "sigma"
    assert row.triggered_by == "manual"


@pytest.mark.asyncio
async def test_trigger_without_repository_means_all(client, db_session):
    resp = await client.post("/api/scheduler/trigger", json={})
    assert resp.status_code == 202
    row = await db_session.get(SyncJob, resp.json()["job_id"])
    assert row.repository is None
    assert "all repositories" in resp.json()["message"]


@pytest.mark.asyncio
async def test_trigger_rejects_unknown_repository(client):
    resp = await client.post("/api/scheduler/trigger", json={"repository": "nope"})
    assert resp.status_code == 400
    assert "Invalid repository" in resp.json()["detail"]
