"""Tests for the /api/actors listing endpoint.

The header stat block renders `groups_with_coverage` and
`software_with_coverage` side by side. In production both currently
equal 26 — traced back to the data (26 distinct G-IDs and 26 distinct
S-IDs carry exact-tag rules; verified against the live corpus
2026-08-11), NOT to a shared variable. These tests pin the invariant
with a fixture where the two counts differ, so a future refactor that
accidentally reuses one count for both stats fails loudly.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.actor_context import actor_context_service
from app.services.mitre import mitre_service


FIXTURE_GROUPS = {
    "G0001": {
        "id": "G0001", "name": "Alpha Group", "aliases": ["AlphaBear"],
        "description": "", "url": "", "references": [], "deprecated": False,
        "techniques": ["T1001", "T1002"], "software": [],
    },
    "G0002": {
        "id": "G0002", "name": "Beta Group", "aliases": [],
        "description": "", "url": "", "references": [], "deprecated": False,
        "techniques": ["T1002"], "software": [],
    },
    "G0003": {
        "id": "G0003", "name": "Gamma Group", "aliases": [],
        "description": "", "url": "", "references": [], "deprecated": False,
        "techniques": [], "software": [],
    },
}

FIXTURE_SOFTWARE = {
    "S0001": {
        "id": "S0001", "name": "Alphaware", "aliases": [], "type": "malware",
        "description": "", "url": "", "references": [], "deprecated": False,
        "platforms": [], "techniques": ["T1001"], "groups": ["G0001"],
    },
    "S0002": {
        "id": "S0002", "name": "SharedTool", "aliases": [], "type": "tool",
        "description": "", "url": "", "references": [], "deprecated": False,
        "platforms": [], "techniques": ["T1002"], "groups": ["G0001", "G0002"],
    },
}

FIXTURE_TECHNIQUES = {
    "T1001": {"id": "T1001", "name": "Tech One", "tactics": [], "deprecated": False, "revoked": False},
    "T1002": {"id": "T1002", "name": "Tech Two", "tactics": [], "deprecated": False, "revoked": False},
}


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


FIXTURE_CONTEXTS = {
    "G0001": {
        "origin_country": "RU",
        "motivations": ["espionage"],
        "target_sectors": ["telecommunications", "government"],
        "target_regions": ["europe"],
        "target_countries": ["Germany"],
        "galaxy_aliases": ["Stone Alpha"],
        "references": [],
        "galaxy_uuid": "u1",
        "galaxy_value": "AlphaBear",
    },
    "G0002": {
        "origin_country": "CN",
        "motivations": ["ransomware"],
        "target_sectors": ["finance"],
        "target_regions": ["north-america"],
        "target_countries": ["United States"],
        "galaxy_aliases": [],
        "references": [],
        "galaxy_uuid": "u2",
        "galaxy_value": "BetaCrew",
    },
}


@pytest.fixture
def mitre_fixture(monkeypatch):
    """Point the mitre_service + context singletons at a tiny
    deterministic catalog."""
    monkeypatch.setattr(mitre_service, "_groups", FIXTURE_GROUPS)
    monkeypatch.setattr(mitre_service, "_software", FIXTURE_SOFTWARE)
    monkeypatch.setattr(mitre_service, "_techniques", FIXTURE_TECHNIQUES)
    monkeypatch.setattr(mitre_service, "_attack_version", "17.1")
    monkeypatch.setattr(mitre_service, "_loaded", True)

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)

    monkeypatch.setattr(actor_context_service, "_contexts", FIXTURE_CONTEXTS)
    monkeypatch.setattr(actor_context_service, "_loaded", True)
    monkeypatch.setattr(actor_context_service, "ensure_loaded", _noop)
    yield


@pytest.fixture
async def client(db_session, mitre_fixture):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_group_and_software_coverage_counts_are_independent(client, db_session):
    """2 groups with exact rules, 1 software with exact rules -> 2 vs 1.

    Guards against the header stat block ever reusing one count for
    both tabs (the suspected — and disproven — cause of the 26/26
    coincidence in production).
    """
    db_session.add_all([
        _rule(title="r1", mitre_groups=["G0001"], mitre_techniques=["T1001"]),
        _rule(title="r2", mitre_groups=["G0002"], mitre_techniques=[]),
        _rule(title="r3", mitre_software=["S0001"], mitre_techniques=["T1002"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_groups"] == 3
    assert data["total_software"] == 2
    assert data["groups_with_coverage"] == 2
    assert data["software_with_coverage"] == 1

    # Each count must match a recount over its own per-item list.
    assert data["groups_with_coverage"] == sum(
        1 for g in data["groups"] if g["our_rule_count"] > 0
    )
    assert data["software_with_coverage"] == sum(
        1 for s in data["software"] if s["our_rule_count"] > 0
    )


# ── Filtered mode (Phase 4) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_filtered_mode_sector_and_facets(client, db_session):
    db_session.add_all([
        _rule(title="r1", mitre_groups=["G0001"], mitre_techniques=["T1001"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors?sector=telecommunications")
    assert resp.status_code == 200
    data = resp.json()
    assert [i["id"] for i in data["items"]] == ["G0001"]
    assert data["total"] == 1
    # Facet counts for OTHER dimensions reflect the sector filter…
    assert data["facets"]["origin"] == {"RU": 1}
    # …while the sector facet itself ignores it (what would clicking
    # another sector chip produce?).
    assert data["facets"]["sector"] == {"government": 1, "telecommunications": 1, "finance": 1}
    assert data["summary"]["total_groups"] == 3


@pytest.mark.asyncio
async def test_filtered_mode_min_gaps_and_tri_state(client, db_session):
    db_session.add_all([
        _rule(title="r1", mitre_groups=["G0001"], mitre_techniques=["T1001"]),
    ])
    await db_session.commit()

    # G0001: covers T1001, gap T1002 -> 1 gap. G0002: gap T1002 -> 1.
    # G0003: no techniques -> 0 gaps.
    resp = await client.get("/api/actors?min_gaps=1")
    assert {i["id"] for i in resp.json()["items"]} == {"G0001", "G0002"}

    resp = await client.get("/api/actors?min_gaps=1&has_exact_rules=true")
    assert [i["id"] for i in resp.json()["items"]] == ["G0001"]

    resp = await client.get("/api/actors?min_gaps=1&has_exact_rules=false")
    assert [i["id"] for i in resp.json()["items"]] == ["G0002"]


@pytest.mark.asyncio
async def test_filtered_mode_q_matches_galaxy_alias(client, db_session):
    resp = await client.get("/api/actors?q=stone+alpha")
    assert [i["id"] for i in resp.json()["items"]] == ["G0001"]


@pytest.mark.asyncio
async def test_filtered_mode_sort_and_pagination(client, db_session):
    resp = await client.get("/api/actors?sort=name&order=asc&page=1&per_page=2")
    data = resp.json()
    assert [i["name"] for i in data["items"]] == ["Alpha Group", "Beta Group"]
    assert data["total"] == 3
    resp = await client.get("/api/actors?sort=name&order=asc&page=2&per_page=2")
    assert [i["name"] for i in resp.json()["items"]] == ["Gamma Group"]


@pytest.mark.asyncio
async def test_filtered_mode_invalid_sort_is_400(client, db_session):
    resp = await client.get("/api/actors?sort=bogus")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_software_defaults_to_used_by_actor_count(client, db_session):
    resp = await client.get("/api/actors?kind=software")
    data = resp.json()
    assert [i["id"] for i in data["items"]] == ["S0002", "S0001"]
    assert data["items"][0]["used_by_actor_count"] == 2
    assert data["facets"]["type"] == {"malware": 1, "tool": 1}


@pytest.mark.asyncio
async def test_software_type_and_used_by_actor_filters(client, db_session):
    resp = await client.get("/api/actors?kind=software&type=tool")
    assert [i["id"] for i in resp.json()["items"]] == ["S0002"]

    resp = await client.get("/api/actors?kind=software&used_by_actor=g0002")
    assert [i["id"] for i in resp.json()["items"]] == ["S0002"]

    resp = await client.get("/api/actors?kind=software&used_by_actor=G0001")
    assert {i["id"] for i in resp.json()["items"]} == {"S0001", "S0002"}


# ── Mention counts in list responses ────────────────────────────────

@pytest.mark.asyncio
async def test_list_carries_mention_counts_from_merged_aliases(client, db_session):
    db_session.add_all([
        # Mentions G0001 via its galaxy alias, no exact tag — the
        # "0 exact rules but N mentions" signal.
        _rule(title="Stone Alpha implant staging"),
        _rule(title="Unrelated PowerShell rule"),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors?kind=groups&sort=mention_count&order=desc")
    items = resp.json()["items"]
    assert items[0]["id"] == "G0001"
    assert items[0]["mention_count"] == 1
    assert items[0]["our_rule_count"] == 0
    assert all(i["mention_count"] == 0 for i in items[1:])


# ── Navigator layer export (Phase 6) ───────────────────────────────

@pytest.mark.asyncio
async def test_actor_navigator_layer_coverage_mode(client, db_session):
    db_session.add_all([
        _rule(title="Rule A", mitre_techniques=["T1001"]),
        _rule(title="Rule B", mitre_techniques=["T1001"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors/G0001/navigator-layer")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    layer = resp.json()

    assert layer["versions"] == {"attack": "17.1", "navigator": "5.1.0", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    # One entry per technique the actor uses; zeros stay enabled.
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1001", "T1002"}
    assert by_id["T1001"]["score"] == 2
    assert "Rule A | Rule B" == by_id["T1001"]["comment"]
    assert by_id["T1002"]["score"] == 0
    assert by_id["T1002"]["enabled"] is True
    assert layer["gradient"]["maxValue"] == 2
    meta = {m["name"]: m["value"] for m in layer["metadata"]}
    assert meta["actor"] == "Alpha Group (G0001)"
    assert meta["match_mode"] == "coverage"
    assert "weighted_coverage" in meta and "generated" in meta


@pytest.mark.asyncio
async def test_actor_navigator_layer_exact_mode_restricts_rules(client, db_session):
    db_session.add_all([
        # Tags the actor AND T1001.
        _rule(title="Tagged rule", mitre_groups=["G0001"], mitre_techniques=["T1001"]),
        # Covers T1001 but not tagged with the actor — must not count
        # in exact mode.
        _rule(title="Untagged rule", mitre_techniques=["T1001"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors/G0001/navigator-layer?match_mode=exact")
    by_id = {t["techniqueID"]: t for t in resp.json()["techniques"]}
    assert by_id["T1001"]["score"] == 1
    assert by_id["T1001"]["comment"] == "Tagged rule"


@pytest.mark.asyncio
async def test_software_navigator_layer_alias_route(client, db_session):
    resp = await client.get("/api/software/S0001/navigator-layer")
    assert resp.status_code == 200
    layer = resp.json()
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1001"}

    resp = await client.get("/api/software/G0001/navigator-layer")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_bulk_navigator_layer_for_filter_set(client, db_session):
    db_session.add_all([_rule(title="Rule A", mitre_techniques=["T1001"])])
    await db_session.commit()

    resp = await client.get("/api/actors/navigator-layer?sector=telecommunications")
    assert resp.status_code == 200
    layer = resp.json()
    # Only G0001 targets telecom -> union of its techniques.
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1001", "T1002"}
    assert by_id["T1001"]["comment"].startswith("used by 1/1 filtered actors")

    resp = await client.get("/api/actors/navigator-layer?sector=nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_covered_technique_count_uses_technique_tags(client, db_session):
    """covered_technique_count counts techniques with any rule, per actor."""
    db_session.add_all([
        _rule(title="r1", mitre_techniques=["T1001"]),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors")
    data = resp.json()
    by_id = {g["id"]: g for g in data["groups"]}

    # G0001 uses T1001 + T1002; only T1001 has a rule.
    assert by_id["G0001"]["technique_count"] == 2
    assert by_id["G0001"]["covered_technique_count"] == 1
    # G0002 uses only T1002 — uncovered.
    assert by_id["G0002"]["covered_technique_count"] == 0
