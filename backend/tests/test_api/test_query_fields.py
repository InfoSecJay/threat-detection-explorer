"""/api/query/fields and the Lucene `q=` error flow on /detections (#24).

The field registry endpoint is what the Query Reference page renders,
so its shape is a contract; the error flow is what the search bar
turns into an inline hint, so the 400 body (error / message /
position / suggestion) is one too.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.query_parser import QUERYABLE_FIELDS


@pytest.fixture
async def client(db_session):
    db_session.add(Detection(
        id="sigma:one", source="sigma", source_file="a.yml", source_repo_url="https://example.test",
        title="Suspicious PowerShell", description="", severity="high", status="stable",
        language="sigma", detection_logic="x", raw_content="x",
        mitre_tactics=[], mitre_techniques=["T1059"], tags=[], platforms=["windows"],
        event_types=[], data_sources=[], extracted_event_ids=[], extracted_process_names=[],
        extracted_api_actions=[],
    ))
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_fields_registry_shape_matches_parser(client):
    r = await client.get("/api/query/fields")
    assert r.status_code == 200
    fields = r.json()["fields"]
    assert len(fields) == len(QUERYABLE_FIELDS) >= 10
    aliases = set()
    for f in fields:
        assert set(f) == {"aliases", "kind", "columns", "description", "examples"}
        assert f["aliases"] and f["columns"] and f["description"]
        assert f["kind"] in {"text", "text_multi", "list", "list_substring", "list_mitre_group", "list_mitre_software", "bool", "int"}, f["kind"]
        for a in f["aliases"]:
            assert a not in aliases, f"alias {a!r} claimed twice"
            aliases.add(a)
    # The names the docs page and the search bar both rely on.
    assert {"source", "technique", "severity"} <= aliases


@pytest.mark.asyncio
async def test_q_happy_path_filters_results(client):
    hit = await client.get("/api/detections", params={"q": "source:sigma AND technique:T1059"})
    assert hit.status_code == 200 and hit.json()["total"] == 1
    miss = await client.get("/api/detections", params={"q": "source:splunk"})
    assert miss.status_code == 200 and miss.json()["total"] == 0


@pytest.mark.asyncio
async def test_q_unknown_field_returns_400_with_suggestion(client):
    r = await client.get("/api/detections", params={"q": "sourc:sigma"})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["error"] == "query_parse_error"
    assert "sourc" in detail["message"]
    assert detail["suggestion"] == "source"


@pytest.mark.asyncio
async def test_q_syntax_error_returns_400_with_position(client):
    r = await client.get("/api/detections", params={"q": "source:(sigma"})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["error"] == "query_parse_error"
    assert detail["message"]
    assert set(detail) == {"error", "message", "position", "suggestion"}


@pytest.mark.asyncio
async def test_facets_share_the_q_error_contract(client):
    r = await client.get("/api/detections/facets", params={"q": "sourc:sigma"})
    assert r.status_code == 400
    assert r.json()["detail"]["suggestion"] == "source"
