"""Tombstones for upstream-removed rules (#87 / teardown F11)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.ingestion import IngestionService
from app.services.tombstones import get_tombstone, record_removed


def _rule(id_, run, title="Doomed rule title", techniques=None):
    return Detection(
        id=id_, source="sigma", source_file=f"{id_}.yml", source_repo_url="https://x",
        title=title, detection_logic="selection: x", language="sigma", raw_content="raw",
        severity="high", status="stable", rule_id=f"rid-{id_}",
        mitre_techniques=techniques or ["T1059"], sync_run_id=run,
    )


@pytest.mark.asyncio
async def test_cleanup_preserves_then_deletes(db_session):
    db_session.add_all([
        _rule("gone", run="old-run"),
        _rule("stays", run="new-run", title="Survivor rule title"),
    ])
    await db_session.commit()

    svc = IngestionService(db_session)
    await svc._cleanup_stale_rules("sigma", "new-run")

    assert await db_session.get(Detection, "gone") is None
    tomb = await get_tombstone(db_session, "gone")
    assert tomb is not None and tomb["removed"] is True
    assert tomb["title"] == "Doomed rule title"
    assert tomb["last_seen"]["detection_logic"] == "selection: x"
    # Successors: the surviving rule shares T1059.
    assert any(s["id"] == "stays" for s in tomb["successors"])
    # Upstream rule id also resolves the tombstone.
    assert (await get_tombstone(db_session, "rid-gone"))["id"] == "gone"


@pytest.mark.asyncio
async def test_detail_route_serves_410_with_history(db_session):
    d = _rule("dead", run="r1")
    db_session.add(d)
    await db_session.commit()
    await record_removed(db_session, [d])
    await db_session.delete(d)  # ORM delete so the identity map lets go too
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/detections/dead")
        assert r.status_code == 410
        body = r.json()
        assert body["removed"] is True and body["title"] == "Doomed rule title"
        # Bots get a tombstone page, not a 404.
        pre = await c.get("/api/prerender/detection/dead")
        assert pre.status_code == 200 and "removed upstream" in pre.text
        # Unknown ids still 404.
        assert (await c.get("/api/detections/never-existed")).status_code == 404
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_reappearing_rule_serves_live_not_tombstone(db_session):
    d = _rule("back", run="r1")
    db_session.add(d)
    await db_session.commit()
    await record_removed(db_session, [d])  # tombstoned but still live

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/detections/back")
        assert r.status_code == 200 and r.json()["id"] == "back"
    app.dependency_overrides.pop(get_db, None)
