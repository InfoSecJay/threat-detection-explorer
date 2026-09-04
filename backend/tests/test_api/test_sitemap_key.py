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
    finally:
        app.dependency_overrides.pop(get_db, None)
