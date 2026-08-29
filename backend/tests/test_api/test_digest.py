"""Weekly digest JSON + RSS feeds."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import trending as trending_routes
from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.models.sync_job import SyncJob
from app.services import coverage_snapshot, digest as digest_service

NOW = datetime(2026, 8, 29, 12, 0, 0)


@pytest.fixture
async def client(db_session, monkeypatch):
    for mod in (trending_routes, coverage_snapshot, digest_service):
        monkeypatch.setattr(mod, "utcnow", lambda: NOW)

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(**kw) -> Detection:
    base = dict(
        source="sigma", source_file="rules/x.yml", source_repo_url="https://example.test",
        title="Rule", detection_logic="x", language="sigma", raw_content="raw", severity="high",
        status="stable", description="A description & more",
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def seeded(db_session):
    db_session.add_all([
        _rule(title="Fresh sigma", rule_created_date=NOW - timedelta(days=1), mitre_techniques=["T1059"],
              data_sources=["sysmon"], quality_score=72, source_rule_url="https://github.com/x/a.yml"),
        _rule(title="Fresh splunk", source="splunk", language="spl",
              rule_created_date=NOW - timedelta(days=2), mitre_techniques=["T1651"], data_sources=["aws_cloudtrail"]),
        _rule(title="Old rule", rule_created_date=NOW - timedelta(days=40), rule_modified_date=NOW - timedelta(days=3)),
    ])
    db_session.add_all([
        SyncJob(job_type="full", triggered_by="scheduled", status="completed", completed_at=NOW - timedelta(hours=6),
                repository_results={"sigma": {"ingest_success": True, "rules_stored": 10}}),
        SyncJob(job_type="full", triggered_by="scheduled", status="completed", completed_at=NOW - timedelta(days=8),
                repository_results={"sigma": {"ingest_success": True, "rules_stored": 7}}),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_digest_composes_every_section(client, seeded):
    resp = await client.get("/api/digest", params={"days": 7})
    assert resp.status_code == 200
    d = resp.json()
    assert d["period"]["days"] == 7 and d["generated_at"].endswith("Z")
    assert d["summary"]["total_rules"] == 3
    assert d["summary"]["created"] == 2 and d["summary"]["modified"] == 1
    assert d["summary"]["created_by_source"] == {"sigma": 1, "splunk": 1}
    assert d["source_deltas"]["by_source"]["sigma"]["delta"] == 3
    assert [r["title"] for r in d["new_rules"]] == ["Fresh sigma", "Fresh splunk"]
    assert d["new_rules"][0]["quality_score"] == 72
    assert d["new_rules"][0]["created"].endswith("Z")
    assert [e["data_source"] for e in d["emerging_data_sources"]] == ["aws_cloudtrail", "sysmon"]
    assert d["newly_covered"]["method"] == "rule_dates"
    assert d["momentum"]["method"] in ("no_data", "insufficient_history", "snapshot")


@pytest.mark.asyncio
async def test_digest_validates_window(client):
    assert (await client.get("/api/digest", params={"days": 0})).status_code == 422
    assert (await client.get("/api/digest", params={"days": 91})).status_code == 422


@pytest.mark.asyncio
async def test_new_rules_feed_is_valid_rss(client, seeded):
    resp = await client.get("/api/digest/feed.xml")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/rss+xml")
    root = ET.fromstring(resp.content)
    assert root.tag == "rss"
    items = root.findall("./channel/item")
    assert [i.findtext("title") for i in items] == ["[sigma] Fresh sigma", "[splunk] Fresh splunk"]
    first = items[0]
    assert first.findtext("link").endswith("/detections/" + first.findtext("guid").split(":", 1)[1])
    assert "A description & more" in first.findtext("description")
    assert "hygiene 72" in first.findtext("description")
    assert [c.text for c in first.findall("category")] == ["sigma", "T1059"]
    assert first.findtext("pubDate").endswith("GMT")


@pytest.mark.asyncio
async def test_newly_covered_feed_is_valid_rss(client, seeded):
    resp = await client.get("/api/digest/newly-covered.xml", params={"days": 30})
    assert resp.status_code == 200
    root = ET.fromstring(resp.content)
    titles = [i.findtext("title") for i in root.findall("./channel/item")]
    assert any(t.startswith("T1059") for t in titles)
    assert any(t.startswith("T1651") for t in titles)
    links = [i.findtext("link") for i in root.findall("./channel/item")]
    assert all("/mitre/T" in l for l in links)
