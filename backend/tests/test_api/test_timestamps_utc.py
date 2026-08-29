"""API timestamps are zone-qualified (#52).

Storage is naive UTC; the wire format must carry a trailing `Z` so
JavaScript (and any other consumer) parses it as UTC rather than local
time. Covers the helper, the pydantic base, and two live routes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.schemas import DetectionResponse, RepositoryResponse
from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.models.sync_job import SyncJob
from app.utils.datetime_utils import to_utc_iso


class TestToUtcIso:
    def test_naive_gets_z(self):
        assert to_utc_iso(datetime(2026, 8, 29, 18, 0, 0)) == "2026-08-29T18:00:00Z"

    def test_microseconds_preserved(self):
        assert to_utc_iso(datetime(2026, 8, 29, 18, 0, 0, 123456)) == "2026-08-29T18:00:00.123456Z"

    def test_aware_converted_to_utc(self):
        plus_two = timezone(timedelta(hours=2))
        assert to_utc_iso(datetime(2026, 8, 29, 20, 0, 0, tzinfo=plus_two)) == "2026-08-29T18:00:00Z"

    def test_none_passthrough(self):
        assert to_utc_iso(None) is None


def test_repository_response_serializes_with_z():
    resp = RepositoryResponse(
        id="r1", name="sigma", url="https://x", last_commit_hash=None,
        last_sync_at=datetime(2026, 8, 29, 14, 45, 47), rule_count=1, status="idle",
        error_message=None, created_at=datetime(2026, 1, 25, 2, 26, 33),
    )
    data = resp.model_dump(mode="json")
    assert data["last_sync_at"] == "2026-08-29T14:45:47Z"
    assert data["created_at"] == "2026-01-25T02:26:33Z"


def test_detection_response_null_dates_stay_null():
    resp = DetectionResponse(
        id="d1", source="sigma", source_file="a.yml", source_repo_url="https://x",
        title="t", severity="high", status="stable", detection_logic="x", raw_content="raw",
        rule_created_date=None, rule_modified_date=None,
        created_at=datetime(2026, 8, 29, 6, 0, 0), updated_at=datetime(2026, 8, 29, 6, 0, 0),
    )
    data = resp.model_dump(mode="json")
    assert data["rule_created_date"] is None
    assert data["updated_at"] == "2026-08-29T06:00:00Z"


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_scheduler_jobs_route_emits_z(client, db_session):
    db_session.add(SyncJob(
        job_type="full", triggered_by="scheduled", status="completed",
        started_at=datetime(2026, 8, 29, 6, 0, 0), completed_at=datetime(2026, 8, 29, 6, 30, 0),
        created_at=datetime(2026, 8, 29, 6, 0, 0),
    ))
    await db_session.commit()
    resp = await client.get("/api/scheduler/jobs")
    assert resp.status_code == 200
    job = resp.json()[0]
    assert job["started_at"] == "2026-08-29T06:00:00Z"
    assert job["completed_at"] == "2026-08-29T06:30:00Z"
    assert job["created_at"].endswith("Z")


@pytest.mark.asyncio
async def test_detection_list_and_export_emit_z(client, db_session):
    db_session.add(Detection(
        source="sigma", source_file="a.yml", source_repo_url="https://x", title="t",
        detection_logic="x", language="sigma", raw_content="raw",
        rule_created_date=datetime(2026, 8, 20, 12, 0, 0),
    ))
    await db_session.commit()

    listing = await client.get("/api/detections", params={"limit": 1})
    assert listing.status_code == 200
    item = listing.json()["items"][0]
    assert item["rule_created_date"] == "2026-08-20T12:00:00Z"
    assert item["created_at"].endswith("Z")

    export = await client.post("/api/export", json={"format": "json"})
    assert export.status_code == 200
    row = export.json()[0]
    assert row["rule_created_date"] == "2026-08-20T12:00:00Z"
    assert row["updated_at"].endswith("Z")
    assert row["rule_modified_date"] is None
