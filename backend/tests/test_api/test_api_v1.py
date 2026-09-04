"""Versioned public surface (#92 / teardown S4.8).

Routers mount at /api/v1; the bare /api/<path> form is a permanent alias;
Swagger and the spec live under /api so the apex proxy can serve them;
the old root /docs and /openapi.json redirect.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app


@pytest_asyncio.fixture
async def client(db_session):
    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_v1_and_unversioned_paths_answer_the_same(client):
    a = await client.get("/api/v1/detections/statistics")
    b = await client.get("/api/detections/statistics")
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()


@pytest.mark.asyncio
async def test_unversioned_alias_keeps_query_string(client):
    a = await client.get("/api/v1/detections?limit=1&offset=0")
    b = await client.get("/api/detections?limit=1&offset=0")
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()


@pytest.mark.asyncio
async def test_health_is_not_versioned(client):
    r = await client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_docs_and_spec_live_under_api(client):
    docs = await client.get("/api/docs")
    assert docs.status_code == 200 and "swagger" in docs.text.lower()
    spec = (await client.get("/api/openapi.json")).json()
    assert spec["info"]["version"] == "1.0.0"
    for section in ("Versioning and deprecation", "Fair use", "40 requests per 10 seconds"):
        assert section in spec["info"]["description"]


@pytest.mark.asyncio
async def test_spec_paths_are_versioned_only(client):
    spec = (await client.get("/api/openapi.json")).json()
    paths = list(spec["paths"])
    assert paths, "spec has no paths"
    # /api/health is infrastructure and intentionally unversioned.
    unversioned = [
        p for p in paths
        if p.startswith("/api/") and not p.startswith("/api/v1/") and p != "/api/health"
    ]
    assert unversioned == [], unversioned


@pytest.mark.asyncio
async def test_root_docs_redirect(client):
    for old, new in (("/docs", "/api/docs"), ("/openapi.json", "/api/openapi.json")):
        r = await client.get(old)
        assert r.status_code == 301 and r.headers["location"] == new


@pytest.mark.asyncio
async def test_edge_cache_header_follows_the_prefix(client):
    for path in ("/api/v1/detections/statistics", "/api/detections/statistics"):
        r = await client.get(path)
        assert r.headers.get("cache-control", "").startswith("public, s-maxage=900"), path
