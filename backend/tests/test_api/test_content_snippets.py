"""DX-12 / #167: the list route attaches a content_snippet to each row for
a `content:` query, marks exclusion-only hits, and stays silent otherwise."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection


@pytest_asyncio.fixture
async def client(db_session):
    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(id_: str, title: str, logic: str, observables: list, **kw) -> Detection:
    base = dict(
        id=id_, source="elastic", rule_id=id_, title=title, source_file=f"rules/{id_}.toml",
        source_repo_url="https://example.test", description="", severity="high", status="stable",
        language="eql", detection_logic=logic, raw_content=f"query = '''{logic}'''",
        extracted_observables=observables,
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def corpus(db_session):
    db_session.add_all([
        _rule(
            "allowlist", "Suspicious signed binary",
            'process where event.type == "start" and not process.code_signature.subject_name : "Citrix Systems, Inc."',
            [{"field": "process.code_signature.subject_name", "values": ["Citrix Systems, Inc."], "type": "process", "subtype": "signer", "negated": True}],
        ),
        _rule(
            "product", "Citrix NetScaler exploitation",
            'process where process.name : "citrix.exe" and process.args : "--debug"',
            [{"field": "process.name", "values": ["citrix.exe"], "type": "process", "subtype": "name", "negated": False}],
        ),
        _rule("other", "Unrelated rule", 'process where process.name : "calc.exe"', []),
    ])
    await db_session.commit()


@pytest.mark.asyncio
async def test_content_query_rows_carry_a_snippet_with_exclusions_marked(client, corpus):
    rows = (await client.get("/api/v1/detections?q=content:citrix&limit=10")).json()["items"]
    by_id = {r["id"]: r for r in rows}
    assert set(by_id) == {"allowlist", "product"}

    allow = by_id["allowlist"]["content_snippet"]
    assert allow["match"].lower() == "citrix" and allow["term"] == "citrix"
    assert allow["field"] == "detection_logic" and allow["negated"] is True
    assert allow["before"].endswith('subject_name : "')

    prod = by_id["product"]["content_snippet"]
    assert prod["negated"] is False and prod["match"].lower() == "citrix"


@pytest.mark.asyncio
async def test_other_queries_carry_no_snippet(client, corpus):
    rows = (await client.get("/api/v1/detections?q=title:citrix&limit=10")).json()["items"]
    assert rows and all("content_snippet" not in r for r in rows)
    rows = (await client.get("/api/v1/detections?limit=10")).json()["items"]
    assert rows and all("content_snippet" not in r for r in rows)
