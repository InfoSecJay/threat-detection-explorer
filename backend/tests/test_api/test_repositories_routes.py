"""Tests for the /api/repositories routes.

Listing + lookup run against the real app over an in-memory SQLite
session. The sync/ingest endpoints are exercised only at the validation
layer, or with the service method that would clone / walk a checkout
stubbed out: nothing here touches git or the filesystem.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.database import get_db
from app.main import app
from app.models.repository import Repository
from app.services.ingestion import IngestionService
from app.services.repository_sync import ALL_REPOSITORY_NAMES, RepositorySyncService


@pytest.fixture
async def client(db_session, monkeypatch):
    # The sync/ingest/trigger routes sit behind the admin gate (#74);
    # these tests exercise the handlers, so authenticate the client.
    monkeypatch.setattr(settings, "admin_token", "admin-test-token")

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test",
        headers={"X-Admin-Token": "admin-test-token"},
    ) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def no_real_work(monkeypatch):
    """Belt and braces: any path that would clone or ingest fails loudly."""

    async def _boom(self, name):
        raise AssertionError(f"real work attempted for {name}")

    monkeypatch.setattr(RepositorySyncService, "sync_repository", _boom)
    monkeypatch.setattr(IngestionService, "ingest_repository", _boom)
    yield


def _repo(**kw) -> Repository:
    base = dict(
        name="sigma",
        url="https://github.com/SigmaHQ/sigma",
        status="idle",
        rule_count=0,
    )
    base.update(kw)
    return Repository(**base)


class _FakeStats:
    """Minimal stand-in for IngestionStats: only what the route reads."""

    def __init__(self, stored: int, error_count: int):
        self.stored = stored
        self.error_count = error_count

    def to_dict(self) -> dict:
        return {
            "discovered": self.stored + self.error_count,
            "skipped_by_filter": 0,
            "parsed": self.stored,
            "normalized": self.stored,
            "stored": self.stored,
            "error_count": self.error_count,
            "warning_count": 0,
            "success_rate": 1.0 if not self.error_count else 0.5,
            "duration_seconds": 1.5,
            "errors_by_stage": {},
            "sample_errors": [],
        }


# -- GET /api/repositories -----------------------------------------------


@pytest.mark.asyncio
async def test_list_materialises_every_known_repository(client, db_session, no_real_work):
    """On an empty DB the list creates an idle row per configured source,
    in the canonical order, with the configured URL."""
    resp = await client.get("/api/repositories")
    assert resp.status_code == 200
    rows = resp.json()
    assert [r["name"] for r in rows] == ALL_REPOSITORY_NAMES
    assert all(r["status"] == "idle" for r in rows)
    assert all(r["rule_count"] == 0 for r in rows)
    assert all(r["last_sync_at"] is None for r in rows)
    sigma = rows[0]
    assert sigma["url"] == RepositorySyncService.REPO_CONFIGS["sigma"]["url"]
    assert set(sigma) == {
        "id", "name", "url", "last_commit_hash", "last_sync_at",
        "rule_count", "status", "error_message", "created_at",
    }


@pytest.mark.asyncio
async def test_list_preserves_existing_rows(client, db_session, no_real_work):
    """A repository that already has sync state is returned as-is, not
    reset to idle/0, and the gaps are filled in around it."""
    existing = _repo(
        name="splunk",
        url="https://example.com/custom",
        status="error",
        error_message="Git error: boom",
        rule_count=42,
        last_commit_hash="abc123",
        last_sync_at=datetime(2026, 8, 25, 6, 0, 0),
    )
    db_session.add(existing)
    await db_session.commit()

    resp = await client.get("/api/repositories")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == len(ALL_REPOSITORY_NAMES)
    splunk = next(r for r in rows if r["name"] == "splunk")
    assert splunk["id"] == existing.id
    assert splunk["url"] == "https://example.com/custom"
    assert splunk["status"] == "error"
    assert splunk["error_message"] == "Git error: boom"
    assert splunk["rule_count"] == 42
    assert splunk["last_commit_hash"] == "abc123"
    assert splunk["last_sync_at"].startswith("2026-08-25T06:00:00")


# -- GET /api/repositories/{name} ----------------------------------------


@pytest.mark.asyncio
async def test_get_repository_returns_row_and_404_when_missing(client, db_session, no_real_work):
    repo = _repo(name="elastic", url="https://github.com/elastic/detection-rules", rule_count=7)
    db_session.add(repo)
    await db_session.commit()

    ok = await client.get("/api/repositories/elastic")
    assert ok.status_code == 200
    assert ok.json()["id"] == repo.id
    assert ok.json()["name"] == "elastic"
    assert ok.json()["rule_count"] == 7

    missing = await client.get("/api/repositories/does-not-exist")
    assert missing.status_code == 404
    assert "Repository not found" in missing.json()["detail"]


# -- POST /api/repositories/{name}/sync ----------------------------------


@pytest.mark.asyncio
async def test_sync_rejects_unknown_repository_before_touching_git(client, no_real_work):
    resp = await client.post("/api/repositories/nope/sync")
    assert resp.status_code == 400
    assert "Invalid repository name" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_sync_reports_service_result_for_known_repository(client, monkeypatch):
    calls: list[str] = []

    async def _stub(self, name):
        calls.append(name)
        return True, f"Cloned {name} repository"

    monkeypatch.setattr(RepositorySyncService, "sync_repository", _stub)

    resp = await client.post("/api/repositories/sigma/sync")
    assert resp.status_code == 200
    assert resp.json() == {"success": True, "message": "Cloned sigma repository", "repository": "sigma"}
    assert calls == ["sigma"]


@pytest.mark.asyncio
async def test_sync_failure_is_a_200_with_success_false(client, monkeypatch):
    async def _stub(self, name):
        return False, "Git error: remote unreachable"

    monkeypatch.setattr(RepositorySyncService, "sync_repository", _stub)

    resp = await client.post("/api/repositories/sigma/sync")
    assert resp.status_code == 200
    assert resp.json()["success"] is False
    assert resp.json()["message"] == "Git error: remote unreachable"


@pytest.mark.asyncio
async def test_sync_all_walks_every_repository_in_order(client, monkeypatch):
    calls: list[str] = []

    async def _stub(self, name):
        calls.append(name)
        return name != "splunk", f"done {name}"

    monkeypatch.setattr(RepositorySyncService, "sync_repository", _stub)

    resp = await client.post("/api/repositories/sync-all")
    assert resp.status_code == 200
    rows = resp.json()
    assert calls == ALL_REPOSITORY_NAMES
    assert [r["repository"] for r in rows] == ALL_REPOSITORY_NAMES
    assert [r["success"] for r in rows] == [name != "splunk" for name in ALL_REPOSITORY_NAMES]


# -- POST /api/repositories/{name}/ingest --------------------------------


@pytest.mark.asyncio
async def test_ingest_rejects_unknown_repository(client, no_real_work):
    resp = await client.post("/api/repositories/nope/ingest")
    assert resp.status_code == 400
    assert "Invalid repository name" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_requires_a_prior_sync(client, db_session, no_real_work):
    """Both a missing row and a row with no last_sync_at are refused."""
    db_session.add(_repo(name="splunk", url="https://example.com/splunk", last_sync_at=None))
    await db_session.commit()

    for name in ("sigma", "splunk"):
        resp = await client.post(f"/api/repositories/{name}/ingest")
        assert resp.status_code == 400
        assert "has not been synced yet" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_reports_stats_from_service(client, db_session, monkeypatch):
    db_session.add(_repo(name="sigma", last_sync_at=datetime(2026, 8, 25)))
    await db_session.commit()

    async def _stub(self, name):
        assert name == "sigma"
        return _FakeStats(stored=10, error_count=2)

    monkeypatch.setattr(IngestionService, "ingest_repository", _stub)

    resp = await client.post("/api/repositories/sigma/ingest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["message"] == "Ingested 10 rules from sigma with 2 errors"
    assert data["stats"]["stored"] == 10
    assert data["stats"]["error_count"] == 2
    assert data["stats"]["duration_seconds"] == 1.5


@pytest.mark.asyncio
async def test_ingest_with_nothing_stored_is_not_a_success(client, db_session, monkeypatch):
    db_session.add(_repo(name="sigma", last_sync_at=datetime(2026, 8, 25)))
    await db_session.commit()

    async def _stub(self, name):
        return _FakeStats(stored=0, error_count=3)

    monkeypatch.setattr(IngestionService, "ingest_repository", _stub)

    resp = await client.post("/api/repositories/sigma/ingest")
    assert resp.status_code == 200
    assert resp.json()["success"] is False
    assert "no rules were stored" in resp.json()["message"]


@pytest.mark.asyncio
async def test_ingest_exception_becomes_failed_response_with_empty_stats(client, db_session, monkeypatch):
    db_session.add(_repo(name="sigma", last_sync_at=datetime(2026, 8, 25)))
    await db_session.commit()

    async def _stub(self, name):
        raise RuntimeError("checkout vanished")

    monkeypatch.setattr(IngestionService, "ingest_repository", _stub)

    resp = await client.post("/api/repositories/sigma/ingest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert data["message"] == "Ingestion failed: checkout vanished"
    assert data["stats"]["stored"] == 0
    assert data["stats"]["error_count"] == 1


# -- POST /api/repositories/ingest-all -----------------------------------


@pytest.mark.asyncio
async def test_ingest_all_skips_unsynced_repositories_without_ingesting(client, no_real_work):
    """With nothing synced every entry is a not-synced failure and the
    ingestion service is never invoked (the guard fixture would raise)."""
    resp = await client.post("/api/repositories/ingest-all")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == len(ALL_REPOSITORY_NAMES)
    assert all(r["success"] is False for r in rows)
    assert all("has not been synced yet" in r["message"] for r in rows)
    assert all(r["stats"]["error_count"] == 0 for r in rows)


@pytest.mark.asyncio
async def test_ingest_all_ingests_only_synced_repositories(client, db_session, monkeypatch):
    db_session.add_all([
        _repo(name="sigma", last_sync_at=datetime(2026, 8, 25)),
        _repo(name="splunk", url="https://example.com/splunk", last_sync_at=datetime(2026, 8, 25)),
    ])
    await db_session.commit()

    calls: list[str] = []

    async def _stub(self, name):
        calls.append(name)
        if name == "splunk":
            raise RuntimeError("bad yaml")
        return _FakeStats(stored=5, error_count=0)

    monkeypatch.setattr(IngestionService, "ingest_repository", _stub)

    resp = await client.post("/api/repositories/ingest-all")
    assert resp.status_code == 200
    rows = resp.json()
    assert calls == ["sigma", "splunk"]
    by_index = dict(zip(ALL_REPOSITORY_NAMES, rows))
    assert by_index["sigma"]["success"] is True
    assert by_index["sigma"]["message"] == "Successfully ingested 5 rules from sigma"
    assert by_index["splunk"]["success"] is False
    assert by_index["splunk"]["message"] == "Ingestion failed for splunk: bad yaml"
    assert by_index["splunk"]["stats"]["error_count"] == 1
    assert by_index["elastic"]["success"] is False
    assert "has not been synced yet" in by_index["elastic"]["message"]
