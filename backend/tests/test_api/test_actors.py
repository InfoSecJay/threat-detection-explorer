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


@pytest.fixture
def mitre_fixture(monkeypatch):
    """Point the mitre_service singleton at a tiny deterministic catalog."""
    monkeypatch.setattr(mitre_service, "_groups", FIXTURE_GROUPS)
    monkeypatch.setattr(mitre_service, "_software", FIXTURE_SOFTWARE)
    monkeypatch.setattr(mitre_service, "_techniques", FIXTURE_TECHNIQUES)
    monkeypatch.setattr(mitre_service, "_loaded", True)

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)
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
    assert data["total_software"] == 1
    assert data["groups_with_coverage"] == 2
    assert data["software_with_coverage"] == 1

    # Each count must match a recount over its own per-item list.
    assert data["groups_with_coverage"] == sum(
        1 for g in data["groups"] if g["our_rule_count"] > 0
    )
    assert data["software_with_coverage"] == sum(
        1 for s in data["software"] if s["our_rule_count"] > 0
    )


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
