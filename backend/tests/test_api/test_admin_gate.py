"""Admin gate on the mutating routes (#74 / teardown F05)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.database import get_db
from app.main import app

WRITE_ROUTES = [
    ("post", "/api/repositories/sigma/sync"),
    ("post", "/api/repositories/sync-all"),
    ("post", "/api/repositories/sigma/ingest"),
    ("post", "/api/repositories/ingest-all"),
    ("post", "/api/mitre/refresh"),
    ("post", "/api/scheduler/trigger"),
]


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", WRITE_ROUTES)
async def test_write_routes_404_without_token(client, monkeypatch, method, path):
    monkeypatch.setattr(settings, "admin_token", "secret-token")
    r = await getattr(client, method)(path, json={"job_type": "full"})
    assert r.status_code == 404
    assert r.json()["detail"] == "Not Found"


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", WRITE_ROUTES)
async def test_wrong_token_is_also_404(client, monkeypatch, method, path):
    monkeypatch.setattr(settings, "admin_token", "secret-token")
    r = await getattr(client, method)(path, json={"job_type": "full"}, headers={"X-Admin-Token": "nope"})
    assert r.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", WRITE_ROUTES)
async def test_unset_token_means_routes_are_dead(client, monkeypatch, method, path):
    monkeypatch.setattr(settings, "admin_token", None)
    r = await getattr(client, method)(path, json={"job_type": "full"}, headers={"X-Admin-Token": "anything"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_correct_token_passes_the_gate(client, monkeypatch):
    monkeypatch.setattr(settings, "admin_token", "secret-token")
    # The gate must let the request through to the handler; scheduler
    # trigger is the cheapest to exercise end to end (INSERTs one row).
    r = await client.post(
        "/api/scheduler/trigger", json={"job_type": "full"}, headers={"X-Admin-Token": "secret-token"},
    )
    assert r.status_code == 202
    assert r.json()["job_id"]


# POST-shaped read endpoints: complex query/selection bodies, no mutation.
READ_SHAPED_POSTS = {"/api/detections/search", "/api/export", "/api/compare", "/api/compare/side-by-side"}


@pytest.mark.asyncio
async def test_openapi_spec_carries_no_write_operations(client):
    spec = (await client.get("/openapi.json")).json()
    for path, ops in spec["paths"].items():
        assert "post" not in ops or path in READ_SHAPED_POSTS, f"unexpected write op in public spec: {path}"
        assert "put" not in ops and "delete" not in ops and "patch" not in ops, path


@pytest.mark.asyncio
async def test_read_routes_stay_public(client):
    assert (await client.get("/api/repositories")).status_code == 200
    assert (await client.get("/api/scheduler/jobs?limit=1")).status_code == 200
