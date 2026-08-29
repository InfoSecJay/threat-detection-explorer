"""GET /api/methodology (#32): per-source count scope, generated from
the same discovery config the ingester uses."""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes.methodology import SCOPE_NOTES
from app.database import get_db
from app.main import app
from app.models.repository import Repository
from app.services.repository_sync import ALL_REPOSITORY_NAMES
from app.services.rule_discovery import RuleDiscoveryService


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def test_every_source_has_a_scope_note():
    missing = [n for n in ALL_REPOSITORY_NAMES if not SCOPE_NOTES.get(n)]
    assert missing == [], f"add SCOPE_NOTES for {missing}"


@pytest.mark.asyncio
async def test_methodology_mirrors_discovery_config_and_repo_state(client, db_session):
    db_session.add(Repository(
        name="sigma", url="https://github.com/SigmaHQ/sigma.git",
        last_commit_hash="abc123def456", last_sync_at=datetime(2026, 8, 29, 6, 0, 0),
        rule_count=3783, status="idle",
    ))
    await db_session.commit()

    resp = await client.get("/api/methodology")
    assert resp.status_code == 200
    data = resp.json()
    assert data["generated_at"].endswith("Z")
    assert len(data["principles"]) >= 3

    by_name = {s["name"]: s for s in data["sources"]}
    assert set(by_name) == set(ALL_REPOSITORY_NAMES)

    sigma = by_name["sigma"]
    assert sigma["include_patterns"] == RuleDiscoveryService.DISCOVERY_PATTERNS["sigma"]["include_patterns"]
    assert "deprecated" in sigma["exclude_dirs"]
    assert "rules-placeholder" in sigma["exclude_dirs"]
    assert sigma["last_commit_hash"] == "abc123def456"
    assert sigma["last_sync_at"] == "2026-08-29T06:00:00Z"
    assert sigma["rule_count"] == 3783
    assert sigma["branch"] == "master"
    assert sigma["sparse_checkout"] is None

    # A source with no repository row yet still documents its scope.
    panther = by_name["panther"]
    assert panther["branch"] == "develop"
    assert panther["sparse_checkout"] and "rules/**" in panther["sparse_checkout"]
    assert panther["rule_count"] is None
    assert panther["scope_notes"]
