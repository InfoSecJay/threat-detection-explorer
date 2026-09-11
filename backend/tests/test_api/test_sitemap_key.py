"""Sitemap artifacts persist across deploys keyed on the corpus
fingerprint (#81). A change to the static page list must invalidate
them too, or a new page stays out of the sitemap until the next sync
(corpus-health, 2026-09-03)."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import sitemap
from app.database import get_db
from app.main import app


def test_key_changes_with_the_static_page_list(monkeypatch):
    before = sitemap._key("pages")
    assert before[0] == "sitemap" and before[1].startswith("pages@")
    monkeypatch.setattr(sitemap, "STATIC", [*sitemap.STATIC, "/brand-new-page"])
    after = sitemap._key("pages")
    assert after != before
    # The index lists the section files, and every section shares the version.
    assert sitemap._key("index")[1].split("@")[1] == after[1].split("@")[1]


@pytest.mark.asyncio
async def test_pages_sitemap_lists_every_static_route(db_session):
    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/sitemap-pages.xml")
            assert r.status_code == 200
            for path in sitemap.STATIC:
                assert f"detectionexplorer.io{path}</loc>" in r.text or f"detectionexplorer.io{path}<" in r.text, path
            assert "/methodology/corpus-health" in r.text
            # DX-18: /integrations is a client-side redirect to /intel;
            # listing it spends crawl budget on a redirect.
            assert "/integrations" not in r.text
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_detection_lastmod_is_the_rule_date_not_the_sync_stamp(db_session):
    """DX-18: every sync re-upserts every row and stamps updated_at, so
    all 15k detection URLs shared one lastmod that moved daily. The
    rule's own upstream modified date is the honest value."""
    from datetime import datetime

    from app.models.detection import Detection

    db_session.add(Detection(
        id="sigma:lm", source="sigma", source_file="r.yml", source_repo_url="https://x",
        title="Rule", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable",
        rule_created_date=datetime(2021, 9, 20), rule_modified_date=datetime(2025, 11, 3),
        updated_at=datetime(2026, 9, 10, 2, 5),
    ))
    db_session.add(Detection(
        id="sigma:nodates", source="sigma", source_file="r2.yml", source_repo_url="https://x",
        title="Rule 2", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", updated_at=datetime(2026, 9, 10, 2, 5),
    ))
    await db_session.commit()

    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            body = (await c.get("/api/v1/sitemap-detections.xml")).text
            lm = body.split("/detections/sigma:lm</loc>")[1].split("</lastmod>")[0]
            assert lm.endswith("<lastmod>2025-11-03"), lm
            # No upstream dates at all -> the sync stamp is still a valid fallback.
            nd = body.split("/detections/sigma:nodates</loc>")[1].split("</lastmod>")[0]
            assert nd.endswith("<lastmod>2026-09-10"), nd
    finally:
        app.dependency_overrides.pop(get_db, None)
