"""Tests for health endpoint."""

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app


client = TestClient(app)


def test_health_check():
    """Test health check endpoint returns OK."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "ok"
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
