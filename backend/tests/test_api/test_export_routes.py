"""Tests for POST /api/export (#24 coverage gap): JSON and CSV shapes,
the include_raw flag, id vs filter selection, and the empty-result 404.
"""

from __future__ import annotations

import csv
import io
import json

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
        source="sigma",
        source_file="rules/test.yml",
        source_repo_url="https://example.com/repo",
        title="Test rule",
        detection_logic="selection: x",
        language="sigma",
        raw_content="title: Test rule\nraw: yes",
        severity="high",
        status="stable",
        mitre_techniques=["T1059"],
        tags=["attack.execution"],
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def seeded(db_session):
    rows = [
        _rule(title="Sigma one", source="sigma", raw_content="RAW-1"),
        _rule(title="Sigma two", source="sigma", raw_content="RAW-2",
              extracted_observables=[{
                  "field": "Image", "values": ["powershell.exe"],
                  "type": "process", "subtype": "process_name", "negated": False,
              }]),
        _rule(title="Splunk one", source="splunk", language="spl", raw_content="RAW-3"),
    ]
    db_session.add_all(rows)
    await db_session.commit()
    for r in rows:
        await db_session.refresh(r)
    return rows


# -- JSON ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_json_export_by_ids_omits_raw_by_default(client, seeded):
    ids = [seeded[0].id, seeded[2].id]
    resp = await client.post("/api/export", json={"format": "json", "ids": ids})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "detections_export.json" in resp.headers["content-disposition"]

    data = json.loads(resp.content)
    assert [d["title"] for d in data] == ["Sigma one", "Splunk one"]
    assert all("raw_content" not in d for d in data)
    first = data[0]
    assert first["mitre_techniques"] == ["T1059"]
    assert first["is_building_block"] is False
    assert first["extracted_observables"] == []
    assert first["created_at"]  # timestamps serialized


@pytest.mark.asyncio
async def test_json_export_include_raw(client, seeded):
    resp = await client.post(
        "/api/export", json={"format": "json", "ids": [seeded[0].id], "include_raw": True}
    )
    assert resp.status_code == 200
    assert json.loads(resp.content)[0]["raw_content"] == "RAW-1"


@pytest.mark.asyncio
async def test_json_export_by_filters(client, seeded):
    resp = await client.post(
        "/api/export", json={"format": "json", "filters": {"sources": ["splunk"]}}
    )
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert [d["source"] for d in data] == ["splunk"]


@pytest.mark.asyncio
async def test_export_everything_when_no_ids_or_filters(client, seeded):
    resp = await client.post("/api/export", json={"format": "json"})
    assert resp.status_code == 200
    assert len(json.loads(resp.content)) == 3


@pytest.mark.asyncio
async def test_export_skips_unknown_ids_and_404s_when_nothing_left(client, seeded):
    resp = await client.post("/api/export", json={"format": "json", "ids": ["nope"]})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_404s_when_filter_matches_nothing(client, seeded):
    resp = await client.post(
        "/api/export", json={"format": "csv", "filters": {"sources": ["elastic"]}}
    )
    assert resp.status_code == 404


# -- CSV ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_csv_export_shape(client, seeded):
    resp = await client.post("/api/export", json={"format": "csv"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "detections_export.csv" in resp.headers["content-disposition"]

    rows = list(csv.reader(io.StringIO(resp.content.decode("utf-8"))))
    header, *data = rows
    assert header[:3] == ["id", "source", "source_file"]
    assert header[-4:] == ["rule_created_date", "rule_modified_date", "created_at", "updated_at"]
    assert "raw_content" not in header
    assert len(data) == 3
    assert all(len(r) == len(header) for r in data)

    by_title = {r[header.index("title")]: r for r in data}
    two = by_title["Sigma two"]
    assert two[header.index("extracted_observables")] == "process/process_name Image=powershell.exe"
    assert two[header.index("mitre_techniques")] == "T1059"
    assert two[header.index("is_building_block")] == "false"


@pytest.mark.asyncio
async def test_csv_export_include_raw_adds_last_column(client, seeded):
    resp = await client.post(
        "/api/export", json={"format": "csv", "ids": [seeded[1].id], "include_raw": True}
    )
    assert resp.status_code == 200
    header, row = list(csv.reader(io.StringIO(resp.content.decode("utf-8"))))
    assert header[-1] == "raw_content"
    assert row[-1] == "RAW-2"
