"""Bot prerender pages + OG card images (#76 / F01 F02)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection


@pytest.fixture
async def client(db_session, monkeypatch):
    from app.services.mitre import mitre_service

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)
    monkeypatch.setattr(
        mitre_service, "get_technique",
        lambda tid: {"id": tid, "name": "Command and Scripting Interpreter", "description": "Adversaries abuse interpreters."} if tid == "T1059" else None,
    )
    monkeypatch.setattr(mitre_service, "get_all_groups", lambda: {"G0016": {"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"], "description": "A group."}})
    monkeypatch.setattr(mitre_service, "get_all_software", lambda: {})

    from datetime import datetime

    db_session.add(Detection(
        id="sigma:x", source="sigma", source_file="r.yml", source_repo_url="https://x",
        source_rule_url="https://github.com/SigmaHQ/sigma/blob/master/rules/r.yml",
        title="Suspicious <PowerShell> Cradle", detection_logic="selection: a", language="sigma",
        raw_content="raw", severity="high", status="stable", description="Detects a download cradle & things.",
        mitre_techniques=["T1059.001"],
        rule_created_date=datetime(2021, 9, 20), rule_modified_date=datetime(2025, 11, 3),
    ))
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_detection_prerender_has_full_meta(client):
    r = await client.get("/api/prerender/detection/sigma:x")
    assert r.status_code == 200
    html = r.text
    assert "<title>Suspicious &lt;PowerShell&gt; Cradle · Detection Explorer</title>" in html
    assert '<link rel="canonical" href="https://detectionexplorer.io/detections/sigma:x">' in html
    assert 'property="og:image" content="https://detectionexplorer.io/api/og/detection/sigma:x.png"' in html
    assert 'name="twitter:card" content="summary_large_image"' in html
    assert "T1059.001" in html and "selection: a" in html
    assert "cache-control" in {k.lower() for k in r.headers}
    assert (await client.get("/api/prerender/detection/nope")).status_code == 404


@pytest.mark.asyncio
async def test_technique_actor_and_home_prerender(client):
    t = await client.get("/api/prerender/technique/t1059")
    assert t.status_code == 200 and "T1059" in t.text and "og:image" in t.text
    a = await client.get("/api/prerender/actor/G0016")
    assert a.status_code == 200 and "APT29" in a.text and "Cozy Bear" in a.text
    h = await client.get("/api/prerender/home")
    assert h.status_code == 200 and "og:type" in h.text and "website" in h.text
    assert (await client.get("/api/prerender/technique/T9999")).status_code == 404


@pytest.mark.asyncio
async def test_og_images_are_png_1200x630(client):
    from PIL import Image
    import io as _io

    for path in ("/api/og/detection/sigma:x.png", "/api/og/technique/T1059.png", "/api/og/actor/G0016.png", "/api/og/site.png"):
        r = await client.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-type"] == "image/png"
        img = Image.open(_io.BytesIO(r.content))
        assert img.size == (1200, 630), path
    assert (await client.get("/api/og/detection/nope.png")).status_code == 404


@pytest.mark.asyncio
async def test_read_routes_get_edge_cache_headers(client):
    r = await client.get("/api/detections?limit=1")
    assert r.headers.get("cache-control") == "public, s-maxage=900, stale-while-revalidate=86400"
    # health is not cacheable
    h = await client.get("/api/health")
    assert "s-maxage" not in (h.headers.get("cache-control") or "")


@pytest.mark.asyncio
async def test_corpus_health_prerender_is_citable_html(client):
    r = await client.get("/api/v1/prerender/corpus-health")
    assert r.status_code == 200
    t = r.text
    assert "<h1>Corpus health</h1>" in t
    assert '<link rel="canonical" href="https://detectionexplorer.io/methodology/corpus-health">' in t
    assert "No ATT&amp;CK mapping" in t and "corpus-health.csv" in t
    assert r.headers["cache-control"].startswith("public, s-maxage=3600")


# -- DX-18 -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_prerender_carries_jsonld(client):
    """A rule page is a citable document: license, dates and the
    upstream file it is based on, as schema.org JSON-LD."""
    import json
    import re

    r = await client.get("/api/prerender/detection/sigma:x")
    m = re.search(r'<script type="application/ld\+json">(.*?)</script>', r.text, re.S)
    assert m, "no JSON-LD block"
    data = json.loads(m.group(1))
    assert data["@context"] == "https://schema.org" and data["@type"] == "TechArticle"
    assert data["headline"] == "Suspicious <PowerShell> Cradle"
    assert data["isBasedOn"] == "https://github.com/SigmaHQ/sigma/blob/master/rules/r.yml"
    assert data["license"].startswith("https://github.com/SigmaHQ/Detection-Rule-License")
    assert data["dateCreated"] == "2021-09-20" and data["dateModified"] == "2025-11-03"
    assert data["keywords"] == ["T1059.001"]


@pytest.mark.asyncio
async def test_methodology_query_digest_observables_prerender(client):
    """The four page types that had no bot-facing render at all."""
    m = await client.get("/api/prerender/methodology")
    assert m.status_code == 200 and "<h1>Methodology</h1>" in m.text
    assert '<link rel="canonical" href="https://detectionexplorer.io/methodology">' in m.text
    assert "sigma" in m.text and "Detection Rule License 1.1" in m.text

    q = await client.get("/api/prerender/query")
    assert q.status_code == 200 and "<h1>Query syntax</h1>" in q.text
    assert "actor, group" in q.text  # the field registry, not a hardcoded list

    d = await client.get("/api/prerender/digest")
    assert d.status_code == 200 and "<h1>Digest" in d.text and "New rules" in d.text
    assert '<link rel="canonical" href="https://detectionexplorer.io/digest">' in d.text

    o = await client.get("/api/prerender/observables/process")
    assert o.status_code == 200 and "observables</h1>" in o.text
    assert '<link rel="canonical" href="https://detectionexplorer.io/observables/process">' in o.text


@pytest.mark.asyncio
async def test_prerender_unknowns_are_real_404s(client):
    assert (await client.get("/api/prerender/observables/not-a-kind")).status_code == 404
    assert (await client.get("/api/prerender/digest/not-a-week")).status_code == 404
