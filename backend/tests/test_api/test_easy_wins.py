"""Health detail, sitemap, actors catalog, observables export, related
rules, coverage by data source."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection


def _rule(id_, source, title, **kw):
    base = dict(
        id=id_, source=source, source_file="r.yml", source_repo_url="https://x", title=title,
        detection_logic="x", language="sigma", raw_content="raw", severity="high", status="stable",
        mitre_techniques=[], data_sources=[], extracted_process_names=[], extracted_event_ids=[],
        extracted_registry_keys=[], extracted_api_actions=[], extracted_file_paths=[],
        extracted_network_indicators=[], extracted_source_tables=[], extracted_observables=[],
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def client(db_session, monkeypatch):
    from app.services.mitre import mitre_service

    async def _noop():
        return None

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)
    monkeypatch.setattr(mitre_service, "get_all_techniques", lambda: {"T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["TA0002"]}})
    monkeypatch.setattr(mitre_service, "get_technique", lambda tid: {"id": tid, "name": "Command and Scripting Interpreter", "tactics": ["TA0002"]} if tid == "T1059" else None)
    monkeypatch.setattr(mitre_service, "get_tactic", lambda tid: {"id": tid, "name": "Execution"})
    monkeypatch.setattr(mitre_service, "get_all_groups", lambda: {"G0016": {"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"]}})
    monkeypatch.setattr(mitre_service, "get_all_software", lambda: {"S0002": {"id": "S0002", "name": "Mimikatz", "type": "tool", "aliases": []}})
    monkeypatch.setattr(mitre_service, "get_stats", lambda: {"last_fetch": "t"})
    from app.services.actor_context import actor_context_service
    monkeypatch.setattr(actor_context_service, "ensure_loaded", _noop)
    monkeypatch.setattr(actor_context_service, "get_context", lambda gid: None)

    db_session.add_all([
        _rule("sigma:a", "sigma", "Mimikatz via cmd", mitre_techniques=["T1059"], data_sources=["sysmon"],
              extracted_process_names=["mimikatz.exe", "cmd.exe"], extracted_event_ids=["1"],
              extracted_observables=[{"field": "Image", "values": ["mimikatz.exe"], "type": "process", "subtype": "process_name", "negated": False}]),
        _rule("splunk:b", "splunk", "Mimikatz LSASS", mitre_techniques=["T1059", "T1003"], data_sources=["sysmon"],
              extracted_process_names=["mimikatz.exe"], extracted_registry_keys=[]),
        _rule("sigma:c", "sigma", "cmd only", mitre_techniques=["T1059"], data_sources=["windows_security_event_log"],
              extracted_process_names=["cmd.exe"]),
        _rule("elastic:d", "elastic", "Unrelated", mitre_techniques=["T1566"], data_sources=["o365_audit"]),
    ])
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_health_reports_corpus_stamp(client):
    d = (await client.get("/api/health")).json()
    assert d["status"] == "healthy" and d["corpus"]["rules"] == 4 and "commit" in d


@pytest.mark.asyncio
async def test_sitemap_lists_static_rule_technique_and_actor_pages(client):
    r = await client.get("/api/sitemap.xml")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/xml")
    for loc in ("/digest", "/detections/sigma:a", "/mitre/T1059", "/actors/G0016", "/actors/S0002", "/observables/process"):
        assert f"<loc>https://detectionexplorer.io{loc}</loc>" in r.text
    assert "/observables/resource" not in r.text


@pytest.mark.asyncio
async def test_actors_catalog_is_ids_names_aliases(client):
    d = (await client.get("/api/actors/catalog")).json()
    assert d["groups"] == [{"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"]}]
    assert d["software"][0]["id"] == "S0002" and "description" not in d["software"][0]


@pytest.mark.asyncio
async def test_observables_export_is_one_row_per_value(client):
    r = await client.post("/api/export", json={"format": "observables", "ids": ["sigma:a"]})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("rule_id,source,title,severity,mitre_techniques,type,subtype,field,value,negated")
    assert lines[1].startswith("sigma:a,sigma,Mimikatz via cmd,high,T1059,process,process_name,Image,mimikatz.exe,false")


@pytest.mark.asyncio
async def test_related_rules_rank_shared_behaviour_other_vendors_first(client):
    d = (await client.get("/api/detections/sigma:a/related")).json()
    ids = [r["id"] for r in d["related"]]
    assert ids[0] == "splunk:b"  # technique + mimikatz.exe, other vendor
    assert "sigma:c" in ids and "elastic:d" not in ids
    top = d["related"][0]
    assert top["other_vendor"] is True and any(r.startswith("process mimikatz.exe") for r in top["reasons"])
    assert (await client.get("/api/detections/nope/related")).status_code == 404


@pytest.mark.asyncio
async def test_coverage_by_data_source_matrix(client):
    d = (await client.get("/api/mitre/coverage-by-data-source", params={"limit": 10, "sources": 5})).json()
    assert [c["id"] for c in d["data_sources"]][0] == "sysmon"
    row = next(r for r in d["rows"] if r["technique_id"] == "T1059")
    assert row["technique_name"] == "Command and Scripting Interpreter" and row["tactic"] == "Execution"
    assert row["rules"] == 3 and row["by_data_source"] == {"sysmon": 2, "windows_security_event_log": 1}
