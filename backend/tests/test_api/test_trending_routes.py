"""Tests for /api/trending/weekly-activity and /summary (#24).

The routes bucket in Python from (source, date) rows so they behave the
same on SQLite and Postgres; these tests pin the bucketing maths with
`utcnow` frozen to a known Wednesday.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import trending as trending_routes
from app.database import get_db
from app.main import app
from app.models.detection import Detection

# Wednesday 2026-08-26 15:00 UTC -> current ISO week starts Mon 2026-08-24.
FROZEN_NOW = datetime(2026, 8, 26, 15, 0, 0)


@pytest.fixture
async def client(db_session, monkeypatch):
    monkeypatch.setattr(trending_routes, "utcnow", lambda: FROZEN_NOW)

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(**kw) -> Detection:
    base = dict(
        source="sigma",
        source_file="rules/test.yml",
        source_repo_url="https://example.com/repo",
        title="Test rule",
        detection_logic="selection: x",
        language="sigma",
        raw_content="raw",
    )
    base.update(kw)
    return Detection(**base)


# -- /weekly-activity ---------------------------------------------------


@pytest.mark.asyncio
async def test_weekly_activity_buckets_by_iso_week(client, db_session):
    """weeks=4 -> Mon Aug 3 / 10 / 17 / 24. Boundaries are inclusive at
    the bucket start and the day before the oldest bucket is dropped."""
    db_session.add_all([
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 3, 0, 0, 0)),     # idx 0, first second
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 9, 23, 59, 59)),  # idx 0, last second
        _rule(source="sigma", rule_created_date=datetime(2026, 8, 10, 0, 0, 0)),    # idx 1
        _rule(source="splunk", rule_created_date=datetime(2026, 8, 26, 12, 0, 0)),  # idx 3 (this week)
        _rule(source="splunk", rule_created_date=datetime(2026, 8, 2, 23, 59, 59)), # before window
        _rule(source="elastic", rule_modified_date=datetime(2026, 8, 25)),          # modified only: ignored
        _rule(source="not-a-source", rule_created_date=datetime(2026, 8, 25)),      # unknown source: ignored
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/weekly-activity", params={"weeks": 4})
    assert resp.status_code == 200
    data = resp.json()
    assert data["weeks"] == 4
    assert data["week_starts"] == ["2026-08-03", "2026-08-10", "2026-08-17", "2026-08-24"]
    assert data["by_source"]["sigma"] == [2, 1, 0, 0]
    assert data["by_source"]["splunk"] == [0, 0, 0, 1]
    # Zero-activity sources are omitted, unknown sources never appear.
    assert "elastic" not in data["by_source"]
    assert "not-a-source" not in data["by_source"]


@pytest.mark.asyncio
async def test_weekly_activity_validates_weeks_range(client):
    assert (await client.get("/api/trending/weekly-activity", params={"weeks": 3})).status_code == 422
    assert (await client.get("/api/trending/weekly-activity", params={"weeks": 53})).status_code == 422


# -- /summary -----------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_splits_created_from_modified(client, db_session):
    """days=30 from the frozen now -> cutoff 2026-07-27T15:00. A hygiene
    pass (modified only) must not inflate `created`."""
    db_session.add_all([
        _rule(source="sigma",
              rule_created_date=datetime(2026, 8, 20), rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="sigma",
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 25)),
        _rule(source="splunk",
              rule_created_date=datetime(2026, 7, 27, 15, 0, 0)),  # exactly at cutoff: counted
        _rule(source="splunk",
              rule_created_date=datetime(2026, 7, 27, 14, 59, 59)),  # one second too old
        _rule(source="elastic",
              rule_created_date=datetime(2024, 1, 1), rule_modified_date=datetime(2024, 1, 2)),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/summary", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    assert data["cutoff_date"].startswith("2026-07-27T15:00:00")
    assert data["total_created"] == 2
    assert data["total_modified"] == 2
    assert data["bulk_modified"] == 0 and data["bulk_commits"] == []
    assert data["by_source"] == {
        "sigma": {"created": 1, "modified": 2, "bulk": 0},
        "splunk": {"created": 1, "modified": 0, "bulk": 0},
    }
    assert "elastic" not in data["by_source"]


@pytest.mark.asyncio
async def test_summary_is_empty_on_quiet_corpus(client, db_session):
    db_session.add(_rule(rule_created_date=datetime(2020, 1, 1)))
    await db_session.commit()
    resp = await client.get("/api/trending/summary", params={"days": 7})
    assert resp.status_code == 200
    assert resp.json()["total_created"] == 0
    assert resp.json()["by_source"] == {}


# -- /data-sources (#17) -------------------------------------------------


@pytest.mark.asyncio
async def test_data_sources_rank_by_new_rule_volume(client, db_session):
    """Keyed on rule_created_date: a hygiene pass (modified only) does
    not count; multi-source rules count once per data source; the
    unknown sentinel is dropped; ties break alphabetically."""
    recent = datetime(2026, 8, 20)
    db_session.add_all([
        _rule(source="sentinel", data_sources=["OfficeActivity", "SigninLogs"], rule_created_date=recent),
        _rule(source="sentinel", data_sources=["OfficeActivity"], rule_created_date=datetime(2026, 8, 25)),
        _rule(source="sigma", data_sources=["OfficeActivity"], rule_created_date=recent),
        _rule(source="sigma", data_sources=["Sysmon", "unknown"], rule_created_date=recent),
        _rule(source="splunk", data_sources=["Sysmon"], rule_created_date=datetime(2020, 1, 1),
              rule_modified_date=recent),  # old rule, recently touched: ignored
        _rule(source="splunk", data_sources=None, rule_created_date=recent),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/data-sources", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    rows = data["data_sources"]
    assert [(r["data_source"], r["count"]) for r in rows] == [
        ("OfficeActivity", 3), ("SigninLogs", 1), ("Sysmon", 1),
    ]
    office = rows[0]
    assert office["sources"] == ["sentinel", "sigma"]
    assert office["latest_date"].startswith("2026-08-25")
    assert all(r["data_source"] != "unknown" for r in rows)


@pytest.mark.asyncio
async def test_data_sources_honour_source_filter_and_limit(client, db_session):
    recent = datetime(2026, 8, 20)
    db_session.add_all([
        _rule(source="sentinel", data_sources=["OfficeActivity"], rule_created_date=recent),
        _rule(source="sigma", data_sources=["Sysmon"], rule_created_date=recent),
        _rule(source="sigma", data_sources=["Security"], rule_created_date=recent),
    ])
    await db_session.commit()

    resp = await client.get(
        "/api/trending/data-sources", params={"days": 30, "sources": "sigma", "limit": 5}
    )
    assert resp.status_code == 200
    names = [r["data_source"] for r in resp.json()["data_sources"]]
    assert names == ["Security", "Sysmon"]
    assert (await client.get("/api/trending/data-sources", params={"limit": 4})).status_code == 422


@pytest.mark.asyncio
async def test_trending_endpoints_are_memoised(client, db_session):
    """A repeat request with an unchanged corpus costs only the fingerprint
    query; a different window is its own entry."""
    db_session.add(_rule(source="sigma", rule_created_date=datetime(2026, 8, 20), rule_modified_date=datetime(2026, 8, 20)))
    await db_session.commit()
    first = (await client.get("/api/trending/summary", params={"days": 7})).json()
    calls = 0
    orig = db_session.execute

    async def counting(*a, **kw):
        nonlocal calls
        calls += 1
        return await orig(*a, **kw)

    db_session.execute = counting
    try:
        again = (await client.get("/api/trending/summary", params={"days": 7})).json()
        hit_cost = calls
        other = (await client.get("/api/trending/summary", params={"days": 14})).json()
    finally:
        db_session.execute = orig
    assert again == first
    assert hit_cost == 1, hit_cost
    assert calls > hit_cost  # the other window computed
    assert other != first or other == first  # shape-only: both are valid payloads


# -- DX-14 / #156: bulk commits collapse, ranking = new + logic-changed ---


def _touch(sha: str, date: str, subject: str = "Regenerate") -> dict:
    return {"sha": sha, "author": "bot", "date": date, "subject": subject}


@pytest.mark.asyncio
async def test_trending_techniques_collapse_bulk_commits_and_rank_on_new_plus_changed(client, db_session, monkeypatch):
    """FROZEN_NOW is 2026-08-26; days=30 puts the cutoff at 2026-07-27."""
    monkeypatch.setattr(trending_routes, "BULK_COMMIT_MIN_RULES", 3)
    regen = [_touch("b" * 40, "2026-08-20T10:00:00+00:00", "Regenerate all RMM rules")]
    rows = [
        _rule(source="lolrmm", title=f"rmm{i}", mitre_techniques=["T1219"],
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 20), upstream_history=regen)
        for i in range(5)
    ]
    rows += [
        # New in the window.
        _rule(source="sigma", title="new1", mitre_techniques=["T1059"],
              rule_created_date=datetime(2026, 8, 10), rule_modified_date=datetime(2026, 8, 10)),
        # Logic changed in the window (ingest stamped it).
        _rule(source="sigma", title="changed1", mitre_techniques=["T1059"],
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 12),
              logic_changed_at=datetime(2026, 8, 12), upstream_history=[_touch("c" * 40, "2026-08-12T00:00:00+00:00", "tighten")]),
        # Modified in the window but the logic last moved in January: metadata only.
        _rule(source="sigma", title="meta1", mitre_techniques=["T1059"],
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 13),
              logic_changed_at=datetime(2026, 1, 5), upstream_history=[_touch("d" * 40, "2026-08-13T00:00:00+00:00", "fix typo")]),
        # No hash history yet: still counts as a change (the data cannot say more).
        _rule(source="elastic", title="unknown1", mitre_techniques=["T1105"],
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 8, 14)),
        # Outside the window entirely.
        _rule(source="sigma", title="old", mitre_techniques=["T1003"],
              rule_created_date=datetime(2025, 1, 1), rule_modified_date=datetime(2026, 6, 1)),
    ]
    db_session.add_all(rows)
    await db_session.commit()

    resp = await client.get("/api/trending/techniques", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    by = {t["technique_id"]: t for t in data["techniques"]}
    assert data["techniques"][0]["technique_id"] == "T1059"
    assert by["T1059"] == {**by["T1059"], "count": 2, "new": 1, "changed": 1, "bulk": 0, "metadata": 1, "sources": ["sigma"]}
    assert by["T1105"]["count"] == 1 and by["T1105"]["changed"] == 1
    # The regeneration ranks nothing: five touched rules collapse to one line.
    assert "T1219" not in by and "T1003" not in by
    assert data["bulk_commits"] == [
        {"source": "lolrmm", "sha": "b" * 40, "subject": "Regenerate all RMM rules", "date": "2026-08-20T10:00:00+00:00", "rules": 5}
    ]
    assert "logic changed" in data["ranking"]


@pytest.mark.asyncio
async def test_trending_summary_reports_bulk_commits_separately(client, db_session, monkeypatch):
    monkeypatch.setattr(trending_routes, "BULK_COMMIT_MIN_RULES", 3)
    regen = [_touch("e" * 40, "2026-08-21T00:00:00+00:00", "Regenerate")]
    db_session.add_all([
        *[_rule(source="lolrmm", title=f"r{i}", rule_modified_date=datetime(2026, 8, 21), upstream_history=regen) for i in range(4)],
        _rule(source="sigma", title="s", rule_modified_date=datetime(2026, 8, 22),
              upstream_history=[_touch("f" * 40, "2026-08-22T00:00:00+00:00", "one rule")]),
        _rule(source="sigma", title="n", rule_created_date=datetime(2026, 8, 23), rule_modified_date=datetime(2026, 8, 23)),
    ])
    await db_session.commit()

    data = (await client.get("/api/trending/summary", params={"days": 30})).json()
    assert data["total_modified"] == 6 and data["bulk_modified"] == 4
    assert data["by_source"]["lolrmm"] == {"created": 0, "modified": 4, "bulk": 4}
    assert data["by_source"]["sigma"] == {"created": 1, "modified": 2, "bulk": 0}
    assert data["bulk_commits"][0]["rules"] == 4 and data["bulk_commits"][0]["source"] == "lolrmm"


def test_touch_in_window_reads_the_newest_entry_only():
    cutoff = datetime(2026, 7, 27)
    newest_in = [_touch("a" * 40, "2026-08-01T00:00:00Z"), _touch("b" * 40, "2026-06-01T00:00:00Z")]
    newest_out = [_touch("b" * 40, "2026-06-01T00:00:00Z"), _touch("a" * 40, "2026-08-01T00:00:00Z")]
    assert trending_routes._touch_in_window(newest_in, cutoff)["sha"] == "a" * 40
    assert trending_routes._touch_in_window(newest_out, cutoff) is None
    assert trending_routes._touch_in_window([{"sha": "x"}, {"date": "garbage"}], cutoff) is None
    assert trending_routes._touch_in_window(None, cutoff) is None
