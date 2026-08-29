"""Observable pages: whole-element case-insensitive matching, per-source
/ technique breakdowns, co-occurrence, negation flag, 404s."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection


@pytest.fixture
async def client(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(**kw) -> Detection:
    base = dict(
        source="sigma", source_file="r.yml", source_repo_url="https://x", title="Rule",
        detection_logic="x", language="sigma", raw_content="raw", severity="high", status="stable",
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def seeded(db_session):
    db_session.add_all([
        _rule(title="Mimikatz via cmd", source="sigma", mitre_techniques=["T1003.001"], mitre_tactics=["TA0006"],
              platforms=["windows"], extracted_process_names=["mimikatz.exe", "cmd.exe"], extracted_event_ids=["4688"],
              quality_score=80,
              extracted_observables=[{"field": "Image", "values": ["mimikatz.exe"], "type": "process", "subtype": "process_name", "negated": False}]),
        _rule(title="Mimikatz LSASS", source="splunk", language="spl", severity="critical", mitre_techniques=["T1003.001", "T1003"],
              extracted_process_names=["MIMIKATZ.EXE"], extracted_event_ids=["10"],
              extracted_observables=[{"field": "Processes.process_name", "values": ["MIMIKATZ.EXE"], "type": "process", "subtype": "process_name", "negated": False}]),
        _rule(title="Not mimikatz", source="elastic", extracted_process_names=["notmimikatz.exe"]),
        _rule(title="Excludes mimikatz", source="elastic", extracted_process_names=["mimikatz.exe"],
              extracted_observables=[{"field": "process.name", "values": ["mimikatz.exe"], "type": "process", "subtype": "process_name", "negated": True}]),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_profile_matches_whole_element_case_insensitively(client, seeded):
    resp = await client.get("/api/observables/process/mimikatz.exe")
    assert resp.status_code == 200
    p = resp.json()
    assert p["total_rules"] == 3  # notmimikatz.exe excluded
    assert p["by_source"] == {"elastic": 1, "sigma": 1, "splunk": 1}
    assert p["by_severity"] == {"high": 2, "critical": 1}
    assert p["by_technique"][0] == {"technique_id": "T1003.001", "rules": 2}
    assert p["by_tactic"] == [{"tactic_id": "TA0006", "rules": 1}]
    assert p["negated_in"] == 1
    assert {f["field"] for f in p["fields"]} == {"Image", "Processes.process_name", "process.name"}
    assert p["co_occurring"]["process"] == [{"value": "cmd.exe", "rules": 1}]
    assert {e["value"] for e in p["co_occurring"]["eventid"]} == {"4688", "10"}
    assert p["filter_key"] == "process_names"
    assert [r["title"] for r in p["rules"]] == ["Excludes mimikatz", "Mimikatz via cmd", "Mimikatz LSASS"]


@pytest.mark.asyncio
async def test_top_values_and_type_index(client, seeded):
    resp = await client.get("/api/observables/process", params={"limit": 10})
    assert resp.status_code == 200
    data = resp.json()
    assert data["distinct"] == 3
    assert data["values"][0] == {"value": "mimikatz.exe", "rules": 3, "sources": ["elastic", "sigma", "splunk"]}

    idx = await client.get("/api/observables")
    assert idx.status_code == 200
    kinds = {t["type"]: t for t in idx.json()["types"]}
    assert kinds["process"]["distinct"] == 3 and kinds["eventid"]["distinct"] == 2
    assert kinds["path"]["distinct"] == 0

    per_source = await client.get("/api/observables/process", params={"source": "splunk"})
    assert [v["value"] for v in per_source.json()["values"]] == ["MIMIKATZ.EXE"]


@pytest.mark.asyncio
async def test_unknown_type_and_value_404(client, seeded):
    assert (await client.get("/api/observables/nope/x")).status_code == 404
    assert (await client.get("/api/observables/process/ghost.exe")).status_code == 404


@pytest.mark.asyncio
async def test_path_values_with_slashes_route(client, db_session):
    db_session.add(_rule(title="Sudoers", extracted_file_paths=["/etc/sudoers"]))
    await db_session.commit()
    resp = await client.get("/api/observables/path//etc/sudoers")
    assert resp.status_code == 200
    assert resp.json()["value"] == "/etc/sudoers"
