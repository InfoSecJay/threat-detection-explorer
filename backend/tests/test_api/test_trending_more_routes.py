"""Tests for the remaining /api/trending routes: /techniques, /platforms,
/recent-rules, /use-cases, /newly-covered and /threats.

Companion to test_trending_routes.py (which covers /weekly-activity,
/summary and /data-sources). Same harness: real FastAPI app over an
in-memory SQLite session, `utcnow` frozen to a known Wednesday on every
module that reads the clock, and the MITRE catalog pointed at a tiny
deterministic fixture so technique names resolve without the gitignored
cache.
"""

from __future__ import annotations

from datetime import date, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.routes import trending as trending_routes
from app.database import get_db
from app.main import app
from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.models.detection import Detection
from app.services import coverage_snapshot as coverage_snapshot_service
from app.services.mitre import mitre_service

# Wednesday 2026-08-26 15:00 UTC (same as test_trending_routes.py).
FROZEN_NOW = datetime(2026, 8, 26, 15, 0, 0)
FROZEN_TODAY = date(2026, 8, 26)

FIXTURE_TECHNIQUES = {
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter",
              "tactics": [], "deprecated": False, "revoked": False},
    "T1651": {"id": "T1651", "name": "Cloud Administration Command",
              "tactics": [], "deprecated": False, "revoked": False},
}


@pytest.fixture
def mitre_fixture(monkeypatch):
    """Tiny deterministic technique catalog; T1003 is deliberately absent."""
    monkeypatch.setattr(mitre_service, "_techniques", FIXTURE_TECHNIQUES)
    monkeypatch.setattr(mitre_service, "_loaded", True)

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)
    yield


@pytest.fixture
async def client(db_session, monkeypatch, mitre_fixture):
    # The route module and the coverage service each import `utcnow` by
    # name, so both bindings have to be frozen.
    monkeypatch.setattr(trending_routes, "utcnow", lambda: FROZEN_NOW)
    monkeypatch.setattr(coverage_snapshot_service, "utcnow", lambda: FROZEN_NOW)

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


# -- /techniques --------------------------------------------------------


@pytest.mark.asyncio
async def test_techniques_rank_by_recently_modified_rules(client, db_session):
    """days=30 -> cutoff 2026-07-27T15:00. Keyed on rule_modified_date:
    a created-only rule is ignored; multi-technique rules count once
    per technique; ties break by technique id."""
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059", "T1003"],
              rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="splunk", mitre_techniques=["T1059"],
              rule_modified_date=datetime(2026, 8, 25)),
        _rule(source="elastic", mitre_techniques=["T1059", "T1003"],
              rule_created_date=datetime(2026, 8, 20)),  # never modified: ignored
        _rule(source="sigma", mitre_techniques=["T1003"],
              rule_modified_date=datetime(2026, 1, 1)),  # out of window
        _rule(source="sigma", mitre_techniques=["T1001"],
              rule_modified_date=datetime(2026, 7, 27, 15, 0, 0)),  # exactly at cutoff
        _rule(source="sigma", mitre_techniques=[],
              rule_modified_date=datetime(2026, 8, 20)),  # no techniques
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/techniques", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    assert data["cutoff_date"].startswith("2026-07-27T15:00:00")
    rows = data["techniques"]
    assert [(r["technique_id"], r["count"]) for r in rows] == [
        ("T1059", 2), ("T1001", 1), ("T1003", 1),
    ]
    top = rows[0]
    assert sorted(top["sources"]) == ["sigma", "splunk"]
    assert top["latest_date"].startswith("2026-08-25")


@pytest.mark.asyncio
async def test_techniques_honour_source_platform_and_event_type_filters(client, db_session):
    recent = datetime(2026, 8, 20)
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059"], platforms=["windows"],
              event_types=["process_creation"], rule_modified_date=recent),
        _rule(source="sigma", mitre_techniques=["T1003"], platforms=["linux"],
              event_types=["process_creation"], rule_modified_date=recent),
        _rule(source="splunk", mitre_techniques=["T1001"], platforms=["windows"],
              event_types=["network_connection"], rule_modified_date=recent),
        _rule(source="elastic", mitre_techniques=["T1002"], platforms=["windows"],
              event_types=["process_creation"], rule_modified_date=recent),
    ])
    await db_session.commit()

    def _ids(resp):
        assert resp.status_code == 200
        return [r["technique_id"] for r in resp.json()["techniques"]]

    assert _ids(await client.get("/api/trending/techniques",
                                 params={"sources": "sigma, splunk"})) == ["T1001", "T1003", "T1059"]
    assert _ids(await client.get("/api/trending/techniques",
                                 params={"platforms": "windows"})) == ["T1001", "T1002", "T1059"]
    assert _ids(await client.get("/api/trending/techniques",
                                 params={"event_types": "network_connection"})) == ["T1001"]
    # Filters are ANDed across dimensions.
    assert _ids(await client.get("/api/trending/techniques",
                                 params={"sources": "sigma", "platforms": "windows"})) == ["T1059"]


@pytest.mark.asyncio
async def test_techniques_cap_at_limit(client, db_session):
    db_session.add_all([
        _rule(mitre_techniques=[f"T10{i:02d}"], rule_modified_date=datetime(2026, 8, 20))
        for i in range(7)
    ])
    await db_session.commit()
    resp = await client.get("/api/trending/techniques", params={"limit": 5})
    assert resp.status_code == 200
    assert len(resp.json()["techniques"]) == 5


@pytest.mark.asyncio
async def test_techniques_validate_query_bounds(client):
    for params in ({"days": 6}, {"days": 366}, {"limit": 4}, {"limit": 51}):
        assert (await client.get("/api/trending/techniques", params=params)).status_code == 422


# -- /platforms ---------------------------------------------------------


@pytest.mark.asyncio
async def test_platforms_count_multi_os_rules_once_per_platform(client, db_session):
    """A [windows, linux] rule counts for both; the `unknown` sentinel
    and empty entries are dropped; keyed on rule_modified_date."""
    db_session.add_all([
        _rule(source="sigma", platforms=["windows", "linux"], rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="splunk", platforms=["windows"], rule_modified_date=datetime(2026, 8, 25)),
        _rule(source="sigma", platforms=["unknown", ""], rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="elastic", platforms=["macos"], rule_created_date=datetime(2026, 8, 20)),  # created only
        _rule(source="sigma", platforms=["macos"], rule_modified_date=datetime(2025, 1, 1)),  # out of window
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/platforms", params={"days": 30})
    assert resp.status_code == 200
    rows = resp.json()["platforms"]
    assert [(r["platform"], r["count"]) for r in rows] == [("windows", 2), ("linux", 1)]
    assert sorted(rows[0]["sources"]) == ["sigma", "splunk"]
    assert rows[0]["latest_date"].startswith("2026-08-25")


@pytest.mark.asyncio
async def test_platforms_honour_source_and_event_type_filters(client, db_session):
    recent = datetime(2026, 8, 20)
    db_session.add_all([
        _rule(source="sigma", platforms=["windows"], event_types=["process_creation"], rule_modified_date=recent),
        _rule(source="splunk", platforms=["linux"], event_types=["process_creation"], rule_modified_date=recent),
        _rule(source="sigma", platforms=["macos"], event_types=["file_event"], rule_modified_date=recent),
    ])
    await db_session.commit()

    by_source = await client.get("/api/trending/platforms", params={"sources": "sigma"})
    assert [r["platform"] for r in by_source.json()["platforms"]] == ["macos", "windows"]

    by_event = await client.get("/api/trending/platforms", params={"event_types": "process_creation"})
    assert [r["platform"] for r in by_event.json()["platforms"]] == ["linux", "windows"]


@pytest.mark.asyncio
async def test_platforms_validate_query_bounds(client):
    for params in ({"days": 6}, {"days": 366}, {"limit": 4}, {"limit": 51}):
        assert (await client.get("/api/trending/platforms", params=params)).status_code == 422


# -- /recent-rules ------------------------------------------------------


@pytest.mark.asyncio
async def test_recent_rules_split_created_from_modified(client, db_session):
    """Each list is ordered by its own date column, the `date` field
    carries that column, and undated rules are excluded from that list."""
    db_session.add_all([
        _rule(title="both", source="sigma", severity="high", platforms=["windows"],
              rule_created_date=datetime(2026, 8, 1), rule_modified_date=datetime(2026, 8, 25)),
        _rule(title="created-only", source="splunk",
              rule_created_date=datetime(2026, 8, 10)),
        _rule(title="modified-only", source="elastic",
              rule_modified_date=datetime(2026, 8, 20)),
        _rule(title="undated", source="sigma"),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/recent-rules")
    assert resp.status_code == 200
    data = resp.json()

    created = data["most_recently_created"]
    assert [r["title"] for r in created] == ["created-only", "both"]
    assert created[0]["date"].startswith("2026-08-10")
    assert created[1]["date"].startswith("2026-08-01")

    modified = data["most_recently_modified"]
    assert [r["title"] for r in modified] == ["both", "modified-only"]
    assert modified[0]["date"].startswith("2026-08-25")

    both = modified[0]
    assert both["source"] == "sigma"
    assert both["severity"] == "high"
    assert both["platforms"] == ["windows"]
    assert both["event_types"] == []
    assert set(both) == {"id", "rule_id", "title", "source", "severity", "platforms", "event_types", "date"}


@pytest.mark.asyncio
async def test_recent_rules_days_window_caps_both_lists(client, db_session):
    """days=7 from the frozen now -> cutoff 2026-08-19T15:00."""
    db_session.add_all([
        _rule(title="in", rule_created_date=datetime(2026, 8, 20), rule_modified_date=datetime(2026, 8, 20)),
        _rule(title="edge", rule_created_date=datetime(2026, 8, 19, 15, 0, 0)),
        _rule(title="out", rule_created_date=datetime(2026, 8, 19, 14, 59, 59),
              rule_modified_date=datetime(2026, 8, 19, 14, 59, 59)),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/recent-rules", params={"days": 7})
    assert resp.status_code == 200
    assert [r["title"] for r in resp.json()["most_recently_created"]] == ["in", "edge"]
    assert [r["title"] for r in resp.json()["most_recently_modified"]] == ["in"]


@pytest.mark.asyncio
async def test_recent_rules_honour_filters_and_limit(client, db_session):
    db_session.add_all([
        _rule(title=f"sigma-win-{i}", source="sigma", platforms=["windows"],
              rule_created_date=datetime(2026, 8, i + 1))
        for i in range(6)
    ] + [
        _rule(title="sigma-linux", source="sigma", platforms=["linux"], rule_created_date=datetime(2026, 8, 20)),
        _rule(title="splunk-win", source="splunk", platforms=["windows"], rule_created_date=datetime(2026, 8, 21)),
    ])
    await db_session.commit()

    resp = await client.get(
        "/api/trending/recent-rules",
        params={"sources": "sigma", "platforms": "windows", "limit": 5},
    )
    assert resp.status_code == 200
    titles = [r["title"] for r in resp.json()["most_recently_created"]]
    assert titles == ["sigma-win-5", "sigma-win-4", "sigma-win-3", "sigma-win-2", "sigma-win-1"]


@pytest.mark.asyncio
async def test_recent_rules_validate_query_bounds(client):
    for params in ({"limit": 4}, {"limit": 51}, {"days": 0}, {"days": 366}):
        assert (await client.get("/api/trending/recent-rules", params=params)).status_code == 422


# -- /use-cases ---------------------------------------------------------


@pytest.mark.asyncio
async def test_use_cases_count_each_story_once_per_rule(client, db_session):
    """A rule tagged with two stories counts toward both; empty strings
    and empty arrays are ignored; sources come back sorted."""
    db_session.add_all([
        _rule(source="splunk", use_cases=["Ransomware", "Lateral Movement"],
              rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="sigma", use_cases=["Ransomware"], rule_modified_date=datetime(2026, 8, 25)),
        _rule(source="sigma", use_cases=["", "Phishing"], rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="sigma", use_cases=[], rule_modified_date=datetime(2026, 8, 20)),
        _rule(source="elastic", use_cases=["Ransomware"], rule_created_date=datetime(2026, 8, 20)),  # created only
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/use-cases", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 30
    rows = data["use_cases"]
    assert [(r["use_case"], r["count"]) for r in rows] == [
        ("Ransomware", 2), ("Lateral Movement", 1), ("Phishing", 1),
    ]
    assert rows[0]["sources"] == ["sigma", "splunk"]
    assert rows[0]["latest_date"].startswith("2026-08-25")


@pytest.mark.asyncio
async def test_use_cases_honour_filters(client, db_session):
    recent = datetime(2026, 8, 20)
    db_session.add_all([
        _rule(source="splunk", use_cases=["A"], platforms=["windows"], event_types=["x"], rule_modified_date=recent),
        _rule(source="sigma", use_cases=["B"], platforms=["linux"], event_types=["x"], rule_modified_date=recent),
        _rule(source="sigma", use_cases=["C"], platforms=["windows"], event_types=["y"], rule_modified_date=recent),
    ])
    await db_session.commit()

    def _names(resp):
        assert resp.status_code == 200
        return [r["use_case"] for r in resp.json()["use_cases"]]

    assert _names(await client.get("/api/trending/use-cases", params={"sources": "sigma"})) == ["B", "C"]
    assert _names(await client.get("/api/trending/use-cases", params={"platforms": "windows"})) == ["A", "C"]
    assert _names(await client.get("/api/trending/use-cases", params={"event_types": "x"})) == ["A", "B"]


@pytest.mark.asyncio
async def test_use_cases_validate_query_bounds(client):
    for params in ({"days": 6}, {"days": 366}, {"limit": 4}, {"limit": 51}):
        assert (await client.get("/api/trending/use-cases", params=params)).status_code == 422


# -- /threats -----------------------------------------------------------


@pytest.mark.asyncio
async def test_threats_extract_named_threats_from_vendor_tags(client, db_session):
    """Splunk bare story tags become campaigns (asset/domain + generic
    categories suppressed); `Malfam:` tags become malware; a `story:`
    prefix works for any source; plain ATT&CK tags are not threats."""
    db_session.add_all([
        _rule(source="splunk", title="s1", tags=["lockbit_ransomware", "endpoint", "ransomware"]),
        _rule(source="splunk", title="s2", tags=["lockbit_ransomware"]),
        _rule(source="sublime", title="m1", tags=["Malfam:Emotet"]),
        _rule(source="sigma", title="p1", tags=["story:volt_typhoon", "attack.t1059"]),
        _rule(source="sigma", title="bare", tags=["lockbit_ransomware"]),  # bare tag: splunk-only heuristic
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/threats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == "full_catalog"
    assert data["period_days"] is None
    threats = data["named_threats"]
    assert [(t["name"], t["kind"], t["count"]) for t in threats] == [
        ("Lockbit Ransomware", "campaign", 2),
        ("Emotet", "malware", 1),
        ("Volt Typhoon", "campaign", 1),
    ]
    assert threats[0]["sources"] == ["splunk"]
    assert [e["title"] for e in threats[0]["examples"]] == ["s1", "s2"]
    assert data["cves"] == []


@pytest.mark.asyncio
async def test_threats_extract_and_normalize_cves_once_per_rule(client, db_session):
    """Dot- and dash-separated forms normalize to CVE-YYYY-NNNN; a rule
    mentioning the same CVE in tag + title + description counts once."""
    db_session.add_all([
        _rule(source="sigma", title="CVE-2021-1675 PrintNightmare", tags=["cve.2021-1675"],
              description="Exploitation of cve-2021-1675 via spooler"),
        _rule(source="elastic", title="Spooler abuse", description="See CVE-2021-1675."),
        _rule(source="sigma", title="Palo Alto", description="Covers cve-2024-3400 exploitation"),
        _rule(source="sigma", title="No CVE here", description="CVE-99-1 is not a CVE id"),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/threats")
    assert resp.status_code == 200
    cves = resp.json()["cves"]
    assert [(c["cve"], c["count"]) for c in cves] == [("CVE-2021-1675", 2), ("CVE-2024-3400", 1)]
    assert cves[0]["sources"] == ["elastic", "sigma"]


@pytest.mark.asyncio
async def test_threats_cap_examples_at_three_and_lists_at_limit(client, db_session):
    db_session.add_all(
        [_rule(source="splunk", title=f"lb-{i}", tags=["lockbit_ransomware"]) for i in range(4)]
        + [_rule(source="splunk", title=f"other-{i}", tags=[f"campaign_{i}"]) for i in range(4)]
    )
    await db_session.commit()

    resp = await client.get("/api/trending/threats", params={"limit": 3})
    assert resp.status_code == 200
    threats = resp.json()["named_threats"]
    assert len(threats) == 3
    assert threats[0]["name"] == "Lockbit Ransomware"
    assert threats[0]["count"] == 4
    assert len(threats[0]["examples"]) == 3


@pytest.mark.asyncio
async def test_threats_days_window_accepts_created_or_modified(client, db_session):
    """days=30 -> cutoff 2026-07-27T15:00. A rule created in-window with
    no later edit still counts; a rule touched before the cutoff does not."""
    db_session.add_all([
        _rule(source="splunk", title="new", tags=["new_campaign"],
              rule_created_date=datetime(2026, 8, 20)),
        _rule(source="splunk", title="touched", tags=["touched_campaign"],
              rule_created_date=datetime(2020, 1, 1), rule_modified_date=datetime(2026, 8, 1)),
        _rule(source="splunk", title="stale", tags=["stale_campaign"],
              rule_created_date=datetime(2020, 1, 1), rule_modified_date=datetime(2026, 7, 1)),
        _rule(source="splunk", title="undated", tags=["undated_campaign"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/threats", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["scope"] == "window"
    assert data["period_days"] == 30
    assert [t["name"] for t in data["named_threats"]] == ["New Campaign", "Touched Campaign"]


@pytest.mark.asyncio
async def test_threats_validate_query_bounds(client):
    for params in ({"limit": 2}, {"limit": 31}, {"days": 6}, {"days": 731}):
        assert (await client.get("/api/trending/threats", params=params)).status_code == 422


# -- /newly-covered -----------------------------------------------------


@pytest.mark.asyncio
async def test_newly_covered_falls_back_to_rule_dates_without_snapshots(client, db_session):
    """No snapshot rows -> method=rule_dates. days=30 from the frozen
    today -> cutoff date 2026-07-27. A technique whose earliest rule
    anywhere is in-window is catalog-new; a source whose first rule for
    an already-covered technique is in-window is source-new."""
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059"], rule_created_date=datetime(2020, 1, 1)),
        _rule(source="sigma", mitre_techniques=["T1059"], rule_created_date=datetime(2026, 8, 20)),
        _rule(source="splunk", mitre_techniques=["T1059"], rule_created_date=datetime(2026, 8, 10)),
        _rule(source="sigma", mitre_techniques=["T1651"], rule_created_date=datetime(2026, 8, 15)),
        _rule(source="elastic", mitre_techniques=["T1003"], rule_created_date=datetime(2019, 1, 1)),
        _rule(source="elastic", mitre_techniques=["T1003"]),  # undated: ignored
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/newly-covered", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "rule_dates"
    assert data["window_days"] == 30
    assert data["baseline_date"] is None
    assert data["new_sources"] == []
    assert data["catalog_newly_covered"] == [{
        "technique_id": "T1651",
        "technique_name": "Cloud Administration Command",
        "sources": {"sigma": 1},
        "total_rules": 1,
    }]
    assert data["source_newly_covered"] == [{
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "source": "splunk",
        "rule_count": 1,
        "covered_elsewhere": ["sigma"],
    }]


@pytest.mark.asyncio
async def test_newly_covered_rule_dates_source_filter_scopes_source_list_only(client, db_session):
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059"], rule_created_date=datetime(2020, 1, 1)),
        _rule(source="splunk", mitre_techniques=["T1059"], rule_created_date=datetime(2026, 8, 10)),
        _rule(source="sigma", mitre_techniques=["T1651"], rule_created_date=datetime(2026, 8, 15)),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/newly-covered", params={"days": 30, "sources": "sigma"})
    assert resp.status_code == 200
    data = resp.json()
    assert [e["technique_id"] for e in data["catalog_newly_covered"]] == ["T1651"]
    assert data["source_newly_covered"] == []


@pytest.mark.asyncio
async def test_newly_covered_diffs_against_baseline_snapshot(client, db_session):
    """Baseline = newest snapshot ON OR BEFORE the cutoff (2026-07-27);
    the live corpus is `now`. Rule dates are irrelevant on this path
    (the splunk T1059 rule is years old but absent from the baseline).
    A source with no baseline rows is onboarding -> `new_sources`, not
    a flood of source-new techniques. Technique ids are upper-cased."""
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059"], rule_created_date=datetime(2020, 1, 1)),
        _rule(source="sigma", mitre_techniques=["T1059"], rule_created_date=datetime(2020, 1, 1)),
        _rule(source="splunk", mitre_techniques=["t1059"], rule_created_date=datetime(2019, 1, 1)),
        _rule(source="sigma", mitre_techniques=["T1651"], rule_created_date=datetime(2020, 1, 1)),
        _rule(source="elastic", mitre_techniques=["T1003"], rule_created_date=datetime(2020, 1, 1)),
    ])
    db_session.add_all([
        # Decoys: too old to be the baseline, and after the cutoff.
        MitreCoverageSnapshot(snapshot_date=date(2026, 7, 1), technique_id="T1651", source="sigma", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=date(2026, 8, 1), technique_id="T1059", source="splunk", rule_count=1),
        # The baseline actually used.
        MitreCoverageSnapshot(snapshot_date=date(2026, 7, 20), technique_id="T1059", source="sigma", rule_count=2),
        MitreCoverageSnapshot(snapshot_date=date(2026, 7, 20), technique_id="T1003", source="splunk", rule_count=1),
        # Today's snapshot; the diff reads the live corpus, not this.
        MitreCoverageSnapshot(snapshot_date=FROZEN_TODAY, technique_id="T1059", source="sigma", rule_count=2),
        MitreCoverageSnapshot(snapshot_date=FROZEN_TODAY, technique_id="T1059", source="splunk", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=FROZEN_TODAY, technique_id="T1651", source="sigma", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=FROZEN_TODAY, technique_id="T1003", source="elastic", rule_count=1),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/newly-covered", params={"days": 30})
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "snapshot"
    assert data["baseline_date"] == "2026-07-20"
    assert data["new_sources"] == ["elastic"]
    assert data["catalog_newly_covered"] == [{
        "technique_id": "T1651",
        "technique_name": "Cloud Administration Command",
        "sources": {"sigma": 1},
        "total_rules": 1,
    }]
    assert data["source_newly_covered"] == [{
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "source": "splunk",
        "rule_count": 1,
        "covered_elsewhere": ["sigma"],
    }]


@pytest.mark.asyncio
async def test_newly_covered_snapshot_source_filter_and_unknown_technique_name(client, db_session):
    """`sources` narrows only the per-source list; a technique missing
    from the MITRE catalog serialises with an empty name, not a 500."""
    db_session.add_all([
        _rule(source="sigma", mitre_techniques=["T1059"]),
        _rule(source="splunk", mitre_techniques=["T1059"]),
        _rule(source="splunk", mitre_techniques=["T1003"]),
    ])
    db_session.add_all([
        MitreCoverageSnapshot(snapshot_date=date(2026, 7, 20), technique_id="T1059", source="sigma", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=date(2026, 7, 20), technique_id="T1651", source="splunk", rule_count=1),
    ])
    await db_session.commit()

    resp = await client.get("/api/trending/newly-covered", params={"days": 30, "sources": "sigma"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "snapshot"
    assert data["new_sources"] == []
    assert [(e["technique_id"], e["technique_name"]) for e in data["catalog_newly_covered"]] == [("T1003", "")]
    assert data["source_newly_covered"] == []

    unfiltered = await client.get("/api/trending/newly-covered", params={"days": 30})
    assert [(e["technique_id"], e["source"]) for e in unfiltered.json()["source_newly_covered"]] == [
        ("T1059", "splunk"),
    ]


@pytest.mark.asyncio
async def test_newly_covered_validate_query_bounds(client):
    for params in ({"days": 6}, {"days": 366}, {"limit": 4}, {"limit": 201}):
        assert (await client.get("/api/trending/newly-covered", params=params)).status_code == 422
