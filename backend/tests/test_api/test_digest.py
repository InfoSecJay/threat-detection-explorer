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
from app.services.tombstones import make_tombstone

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
    assert d["summary"]["by_source"] == {"sigma": {"created": 1, "modified": 1}, "splunk": {"created": 1, "modified": 0}}
    assert [r["title"] for r in d["modified_rules"]] == ["Old rule"]
    assert d["themes"][0]["technique_id"] in ("T1059", "T1651") and d["themes"][0]["rules"] == 1
    assert d["themes"][0]["samples"][0]["title"].startswith("Fresh")
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


@pytest.mark.asyncio
async def test_new_rule_is_not_also_counted_as_modified(client, db_session, seeded):
    """A rule created in the window carries a modified date too; it must
    show up once, under new."""
    db_session.add(_rule(title="Fresh and touched", rule_created_date=NOW - timedelta(days=1),
                         rule_modified_date=NOW - timedelta(hours=1)))
    await db_session.commit()
    d = (await client.get("/api/digest", params={"days": 7})).json()
    assert d["summary"]["created"] == 3 and d["summary"]["modified"] == 1
    assert "Fresh and touched" in [r["title"] for r in d["new_rules"]]
    assert "Fresh and touched" not in [r["title"] for r in d["modified_rules"]]


@pytest.mark.asyncio
async def test_digest_lists_rules_removed_upstream_in_the_window(client, db_session, seeded):
    """Deprecations reach the corpus as removals (parsers skip deprecated/
    folders), so the digest's retired list comes from the tombstones."""
    gone = make_tombstone(_rule(id="gone", title="Retired rule", rule_id="rid-gone", severity="low", mitre_techniques=["T1059"]))
    gone.removed_at = NOW - timedelta(days=1)
    stale = make_tombstone(_rule(id="old", title="Long gone", rule_id="rid-old"))
    stale.removed_at = NOW - timedelta(days=20)
    # Not removals: a rule that came back under the same id (the 09-02
    # incident) and one re-keyed to a new id (#86) but still live.
    back = make_tombstone(_rule(id="alive", title="Came back", rule_id="rid-alive"))
    back.removed_at = NOW - timedelta(days=2)
    rekeyed = make_tombstone(_rule(id="old-key", title="Re-keyed", rule_id="rid-rekey"))
    rekeyed.removed_at = NOW - timedelta(days=2)
    db_session.add_all([
        gone, stale, back, rekeyed,
        _rule(id="alive", title="Came back", rule_id="rid-alive", rule_created_date=NOW - timedelta(days=100)),
        _rule(id="new-key", title="Re-keyed", rule_id="rid-rekey", rule_created_date=NOW - timedelta(days=100)),
    ])
    await db_session.commit()

    # A rule re-keyed (#86) and then removed upstream leaves two
    # tombstones for one event; the digest shows it once, newest first.
    twice_old = make_tombstone(_rule(id="twice-old", title="Removed after re-key", rule_id="rid-twice"))
    twice_old.removed_at = NOW - timedelta(days=4)
    twice_new = make_tombstone(_rule(id="twice-new", title="Removed after re-key", rule_id="rid-twice"))
    twice_new.removed_at = NOW - timedelta(days=3)
    db_session.add_all([twice_old, twice_new])
    await db_session.commit()

    d = (await client.get("/api/digest", params={"days": 7})).json()
    assert d["summary"]["removed"] == 2
    assert [r["title"] for r in d["removed_rules"]] == ["Retired rule", "Removed after re-key"]
    assert d["removed_rules"][1]["id"] == "twice-new"
    r = d["removed_rules"][0]
    assert r["source"] == "sigma" and r["severity"] == "low" and r["mitre_techniques"] == ["T1059"]
    assert r["removed"].endswith("Z")
    # Counts elsewhere are untouched: tombstones are not live rules
    # (3 seeded + the two live rules added above).
    assert d["summary"]["total_rules"] == 5


@pytest.mark.asyncio
async def test_feeds_filter_by_source_and_modified_feed_exists(client, seeded):
    resp = await client.get("/api/digest/feed.xml", params={"source": "splunk"})
    assert resp.status_code == 200
    items = ET.fromstring(resp.text).find("channel").findall("item")
    assert [i.findtext("title") for i in items] == ["[splunk] Fresh splunk"]
    assert (await client.get("/api/digest/feed.xml", params={"source": "nope"})).status_code == 400

    resp = await client.get("/api/digest/modified.xml")
    assert resp.status_code == 200
    items = ET.fromstring(resp.text).find("channel").findall("item")
    assert [i.findtext("title") for i in items] == ["[sigma] Old rule"]
    assert items[0].findtext("guid").startswith("detection:") and ":modified:" in items[0].findtext("guid")
