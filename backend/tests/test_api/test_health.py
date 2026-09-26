"""Tests for health endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app


@pytest.mark.asyncio
async def test_health_check(db_session):
    """/api/health answers 200 with the corpus stamp when the query works.

    The query runs against the in-memory test session, not the file
    database under backend/data/: that file only exists on a machine
    that has run the app, so on a clean checkout (CI) the route answered
    503 and this test failed on every run after 9dae1d3 (#97) made
    health execute a real query.
    """

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            response = await c.get("/api/health")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "ok"
    assert data["corpus"]["rules"] == 0
    assert "app" in data


@pytest.mark.asyncio
async def test_health_is_503_when_the_database_is_unreachable():
    """A DB outage must show on /api/health (#97): the 2026-08-31 outage
    kept this endpoint green for five hours because it never ran a
    query. Uptime monitors key on the status code."""

    class DeadSession:
        async def execute(self, *a, **kw):
            raise ConnectionError("db is down")

        async def close(self):
            pass

    async def dead_db():
        yield DeadSession()

    app.dependency_overrides[get_db] = dead_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/health")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["database"].startswith("unreachable")
    assert body["corpus"] == {"rules": None, "updated_at": None}
