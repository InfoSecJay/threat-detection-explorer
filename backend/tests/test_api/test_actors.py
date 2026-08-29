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
        # All-caps English-word alias -- the issue #33 hazard class.
        "id": "G0003", "name": "Gamma Group", "aliases": ["LEAD"],
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
async def test_list_title_mention_promotes_to_dedicated(client, db_session):
    db_session.add_all([
        # Galaxy alias in the TITLE — dedicated tier (issue #34), no
        # longer a mere mention.
        _rule(title="Stone Alpha implant staging"),
        # Galaxy alias in the DESCRIPTION only — referenced tier.
        _rule(
            title="Generic loader detection",
            description="Loader previously used by Stone Alpha operators.",
        ),
        _rule(title="Unrelated PowerShell rule"),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors?kind=groups&sort=mention_count&order=desc")
    items = resp.json()["items"]
    g1 = next(i for i in items if i["id"] == "G0001")
    assert g1["our_rule_count"] == 1   # title hit is dedicated
    assert g1["mention_count"] == 1    # description hit stays referenced
    assert all(
        i["mention_count"] == 0 and i["our_rule_count"] == 0
        for i in items if i["id"] != "G0001"
    )


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


# == Story-label exact + separator-tolerant mention (Salt Typhoon bug) ==
#
# Production case: 60 Splunk ESCU rules carried the actor ONLY as
# use_cases=["Salt Typhoon"] / tags=["story:salt_typhoon"] plus
# advisory URLs in references. Exact showed 0 (ESCU never tags G-IDs)
# and mention showed 4 (\b regex can't cross underscores; use_cases/
# references weren't searched at all).

def _story_rules() -> list[Detection]:
    return [
        # Explicit tag via analytic story named after the actor.
        _rule(title="VTY tampering", use_cases=["Alpha Group"]),
        # Underscore story tag -- mention, not exact.
        _rule(title="Tunnel config", tags=["story:alpha_group"]),
        # Advisory URL in references -- mention.
        _rule(
            title="Log clearing",
            references=["https://blog.example.com/alpha-group-analysis/"],
        ),
        # Alias in prose -- mention.
        _rule(title="AlphaBear staging activity"),
        # Longer story label CONTAINING the name -- mention, NOT exact.
        _rule(title="Recon burst", use_cases=["Alpha Group Campaign 2025"]),
        _rule(title="Unrelated rule"),
    ]


@pytest.mark.asyncio
async def test_detail_dedicated_tier_story_and_title(client, db_session):
    """Dedicated = story label OR name-in-title; disjoint from
    referenced (issue #34), with per-rule match_reasons."""
    db_session.add_all(_story_rules())
    await db_session.commit()

    resp = await client.get("/api/actors/G0001?match_mode=exact")
    assert resp.status_code == 200
    data = resp.json()

    # Story-labeled rule + alias-in-title rule are dedicated.
    assert data["match_counts"]["exact"] == 2
    by_title = {r["title"]: r for r in data["rules"]}
    assert set(by_title) == {"VTY tampering", "AlphaBear staging activity"}
    assert by_title["VTY tampering"]["match_reasons"] == ["story"]
    assert by_title["AlphaBear staging activity"]["match_reasons"] == ["title"]
    # Referenced excludes both dedicated rules: tag + reference +
    # campaign-label mentions remain.
    assert data["match_counts"]["mention"] == 3


@pytest.mark.asyncio
async def test_detail_referenced_tier_is_disjoint_with_reasons(client, db_session):
    db_session.add_all(_story_rules())
    await db_session.commit()

    resp = await client.get("/api/actors/G0001?match_mode=mention")
    by_title = {r["title"]: r for r in resp.json()["rules"]}
    assert set(by_title) == {"Tunnel config", "Log clearing", "Recon burst"}
    assert by_title["Tunnel config"]["match_reasons"] == ["tag"]
    assert by_title["Log clearing"]["match_reasons"] == ["reference"]
    assert by_title["Recon burst"]["match_reasons"] == ["use-case"]


@pytest.mark.asyncio
async def test_list_scores_match_detail_semantics(client, db_session):
    """our_rule_count / mention_count on the list page use the same
    disjoint dedicated/referenced semantics as the detail page."""
    db_session.add_all(_story_rules())
    await db_session.commit()

    resp = await client.get("/api/actors?kind=groups&sort=mention_count&order=desc")
    items = resp.json()["items"]
    g1 = next(i for i in items if i["id"] == "G0001")
    assert g1["our_rule_count"] == 2
    assert g1["mention_count"] == 3


# == Case-sensitive alias matching (issue #33) ======================
# G0003 carries the all-caps alias "LEAD" in this fixture; prose
# "lead" must not count as a mention, literal "LEAD" must.

@pytest.mark.asyncio
async def test_allcaps_alias_does_not_match_prose(client, db_session):
    db_session.add_all([
        _rule(
            title="S3 bucket policy weakened",
            description="Changes that may lead to unauthorized access.",
        ),
        # Exact-case alias in title -> dedicated tier.
        _rule(
            title="LEAD implant staging",
            description="Detects staging activity attributed to LEAD.",
        ),
        # Exact-case alias in description only -> referenced tier.
        _rule(
            title="Registry persistence via print monitor",
            description="Technique observed in LEAD intrusions.",
        ),
    ])
    await db_session.commit()

    resp = await client.get("/api/actors/G0003?match_mode=exact")
    assert resp.status_code == 200
    data = resp.json()
    # Prose "lead" counts nowhere; literal LEAD title is dedicated,
    # literal LEAD description is referenced.
    assert data["match_counts"]["exact"] == 1
    assert [r["title"] for r in data["rules"]] == ["LEAD implant staging"]
    assert data["match_counts"]["mention"] == 1


@pytest.mark.asyncio
async def test_actor_detail_breaks_coverage_down_by_source(client, db_session):
    """#18: per-technique and per-source counts so the UI can show which
    vendor covers which of the actor's techniques."""
    db_session.add_all([
        _rule(title="s1", source="sigma", mitre_techniques=["T1001", "T1002"]),
        _rule(title="s2", source="sigma", mitre_techniques=["T1001"]),
        _rule(title="e1", source="elastic", mitre_techniques=["T1002"]),
        _rule(title="x1", source="splunk", mitre_techniques=["T9999"]),  # not one of G0001's
    ])
    await db_session.commit()

    resp = await client.get("/api/actors/G0001")
    assert resp.status_code == 200
    data = resp.json()
    techs = {t["technique_id"]: t for t in data["techniques"]}
    assert techs["T1001"]["rule_count_by_source"] == {"sigma": 2}
    assert techs["T1002"]["rule_count_by_source"] == {"elastic": 1, "sigma": 1}
    assert data["coverage_by_source"] == {
        "elastic": {"techniques_covered": 1, "rule_count": 1},
        "sigma": {"techniques_covered": 2, "rule_count": 3},
    }
