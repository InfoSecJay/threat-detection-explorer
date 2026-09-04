"""GET /compare/diff (#11): request shape and the matrix it serves."""

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


def _rule(id_: str, source: str, field: str, values: list[str]) -> Detection:
    return Detection(
        id=id_, source=source, source_file=f"{id_}.yml", source_repo_url="https://x",
        title=f"Rule {id_}", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", mitre_techniques=["T1059"], platforms=["windows"],
        extracted_observables=[{"field": field, "values": values, "type": "process", "subtype": "process_name", "negated": False}],
    )


@pytest.fixture
async def seeded(db_session):
    db_session.add_all([
        _rule("r1", "sigma", "Image", ["mshta.exe"]),
        _rule("r2", "elastic", "process.name", ["mshta.exe", "wscript.exe"]),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_diff_requires_two_to_six_ids(client, seeded):
    assert (await client.get("/api/v1/compare/diff", params={"ids": "r1"})).status_code == 400
    assert (await client.get("/api/v1/compare/diff", params={"ids": ",".join(f"x{i}" for i in range(7))})).status_code == 400
    # Duplicates collapse before the count.
    assert (await client.get("/api/v1/compare/diff", params={"ids": "r1,r1"})).status_code == 400


@pytest.mark.asyncio
async def test_diff_404s_unless_two_rules_exist(client, seeded):
    assert (await client.get("/api/v1/compare/diff", params={"ids": "r1,nope"})).status_code == 404


@pytest.mark.asyncio
async def test_diff_keeps_request_order_and_reports_missing(client, seeded):
    resp = await client.get("/api/v1/compare/diff", params={"ids": "r2,r1,ghost"})
    assert resp.status_code == 200
    d = resp.json()
    assert [r["id"] for r in d["rules"]] == ["r2", "r1"]
    assert d["missing_ids"] == ["ghost"]
    mshta = next(o for o in d["observables"] if o["value"] == "mshta.exe")
    assert mshta["shared"] is True and mshta["fields"] == {"r2": ["process.name"], "r1": ["Image"]}
    assert d["summary"]["unique_by_rule"] == {"r2": 1, "r1": 0}
    assert d["axes"]["mitre_techniques"] == [{"value": "T1059", "present_in": ["r2", "r1"]}]
