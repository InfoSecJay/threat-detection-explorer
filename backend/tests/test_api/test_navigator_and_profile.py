"""Navigator layer export for any query + technique profile."""

from __future__ import annotations

from datetime import date

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.models.detection import Detection
from app.services.mitre import mitre_service


@pytest.fixture
def mitre_fixture(monkeypatch):
    monkeypatch.setattr(mitre_service, "_techniques", {
        "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
        "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["TA0006"]},
    })
    monkeypatch.setattr(mitre_service, "_groups", {
        "G0016": {"id": "G0016", "name": "APT29", "techniques": ["T1059", "T1003"], "deprecated": False},
        "G0001": {"id": "G0001", "name": "Old Group", "techniques": ["T1059"], "deprecated": True},
    })
    monkeypatch.setattr(mitre_service, "_software", {
        "S0002": {"id": "S0002", "name": "Mimikatz", "type": "tool", "techniques": ["T1003"], "deprecated": False},
    })
    monkeypatch.setattr(mitre_service, "_attack_version", "17.1")
    monkeypatch.setattr(mitre_service, "_loaded", True)

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)


@pytest.fixture
async def client(db_session, mitre_fixture):
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
        _rule(title="Sigma PS", mitre_techniques=["T1059", "T1059.001"], quality_score=80,
              extracted_process_names=["powershell.exe"], extracted_event_ids=["4104"]),
        _rule(title="Sigma cred", mitre_techniques=["T1003"], quality_score=60,
              extracted_process_names=["mimikatz.exe"]),
        _rule(title="Splunk PS", source="splunk", language="spl", mitre_techniques=["T1059"], severity="critical",
              extracted_process_names=["powershell.exe", "cmd.exe"], extracted_source_tables=["Endpoint.Processes"]),
        _rule(title="No techniques", mitre_techniques=[]),
    ])
    db_session.add_all([
        MitreCoverageSnapshot(snapshot_date=date(2026, 8, 29), technique_id="T1059", source="sigma", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=date(2026, 8, 29), technique_id="T1059", source="splunk", rule_count=1),
        MitreCoverageSnapshot(snapshot_date=date(2026, 8, 20), technique_id="T1059", source="sigma", rule_count=1),
    ])
    await db_session.commit()


# -- navigator export ----------------------------------------------------------


@pytest.mark.asyncio
async def test_navigator_export_scores_techniques_by_rule_count(client, seeded):
    resp = await client.post("/api/export", json={"format": "navigator", "filters": {"sources": ["sigma", "splunk"]}})
    assert resp.status_code == 200
    assert "detection-explorer-layer.json" in resp.headers["content-disposition"]
    layer = resp.json()
    assert layer["versions"] == {"attack": "17.1", "navigator": "5.1.0", "layer": "4.5"}
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1059": 2, "T1059.001": 1, "T1003": 1}
    t1059 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059")
    assert "[sigma] Sigma PS" in t1059["comment"] and "[splunk] Splunk PS" in t1059["comment"]
    assert layer["gradient"]["maxValue"] == 2
    assert "sources=['sigma', 'splunk']" in layer["name"]
    assert {m["name"] for m in layer["metadata"]} == {"generated", "rules", "scope"}


@pytest.mark.asyncio
async def test_navigator_export_by_ids(client, seeded, db_session):
    from sqlalchemy import select
    ids = [r.id for r in (await db_session.execute(select(Detection).where(Detection.title == "Sigma cred"))).scalars()]
    resp = await client.post("/api/export", json={"format": "navigator", "ids": ids})
    assert resp.status_code == 200
    assert [t["techniqueID"] for t in resp.json()["techniques"]] == ["T1003"]
    assert "1 selected rule" in resp.json()["name"]


@pytest.mark.asyncio
async def test_export_format_validation_still_rejects_junk(client, seeded):
    assert (await client.post("/api/export", json={"format": "yaml"})).status_code == 422


# -- technique profile ----------------------------------------------------------


@pytest.mark.asyncio
async def test_technique_profile(client, seeded):
    resp = await client.get("/api/mitre/techniques/t1059/profile")
    assert resp.status_code == 200
    p = resp.json()
    assert p["technique_id"] == "T1059" and p["name"] == "Command and Scripting Interpreter"
    assert p["total_rules"] == 2
    assert p["by_severity"] == {"high": 1, "critical": 1}
    assert list(p["sources"]) == ["sigma", "splunk"]
    assert p["sources"]["sigma"] == {
        "rules": 1, "hygiene_avg": 80.0,
        "observables": {"process": [{"value": "powershell.exe", "rules": 1}], "eventid": [{"value": "4104", "rules": 1}]},
    }
    assert p["sources"]["splunk"]["hygiene_avg"] is None
    assert [o["value"] for o in p["sources"]["splunk"]["observables"]["process"]] == ["powershell.exe", "cmd.exe"]
    assert [g["id"] for g in p["groups"]] == ["G0016"]  # deprecated group excluded
    assert p["software"] == []
    assert p["momentum"] == {"method": "snapshot", "current": 2, "baseline": 1, "delta": 1, "baseline_date": "2026-08-20"}


@pytest.mark.asyncio
async def test_technique_profile_software_and_404(client, seeded):
    resp = await client.get("/api/mitre/techniques/T1003/profile")
    assert resp.status_code == 200
    assert [s["name"] for s in resp.json()["software"]] == ["Mimikatz"]
    assert resp.json()["momentum"]["method"] == "snapshot"
    assert resp.json()["momentum"]["current"] == 0
    assert (await client.get("/api/mitre/techniques/T9999/profile")).status_code == 404
