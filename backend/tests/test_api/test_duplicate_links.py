"""DX-10 / #166: the detail route carries both sides of a duplicate pair,
the statistics route discloses the ports, and the equivalence pass
treats a linked port as the same rule."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.duplicates import write_duplicate_links
from app.services.equivalents import write_equivalent_sources


@pytest_asyncio.fixture
async def client(db_session):
    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _rule(id_: str, source: str, rule_id: str, title: str, **kw) -> Detection:
    base = dict(
        id=id_, source=source, rule_id=rule_id, title=title, source_file=f"{source}/{id_}.py",
        source_repo_url="https://example.test", description="", severity="high", status="stable",
        language="python", detection_logic="x", raw_content="x", mitre_techniques=["T1078"],
        extracted_api_actions=["iam:CreateUser"], extracted_process_names=[],
        extracted_registry_keys=[], extracted_file_paths=[], extracted_network_indicators=[],
        extracted_event_ids=[],
    )
    base.update(kw)
    return Detection(**base)


@pytest.fixture
async def pair(db_session):
    db_session.add_all([
        _rule("p1", "panther", "AWS.IAM.UserCreated", "IAM user created"),
        _rule("py1", "pypanther", "AWS.IAM.UserCreated-prototype", "IAM user created"),
        # A port-source rule with no twin, on a different surface: an
        # ordinary rule for every pass, and no equivalent of the pair.
        _rule("py2", "pypanther", "AWS.IAM.Solo-prototype", "A port with no twin",
              mitre_techniques=["T1530"], extracted_api_actions=["s3:PutBucketPolicy"]),
        # Same API action + technique as the pair: a real equivalent.
        _rule("e1", "elastic", "iam-user-created", "IAM user created (Elastic)", language="kql"),
    ])
    await db_session.commit()
    await write_duplicate_links(db_session)
    await write_equivalent_sources(db_session)


@pytest.mark.asyncio
async def test_detail_carries_both_directions(client, pair):
    port = (await client.get("/api/v1/detections/py1")).json()
    assert port["duplicate_of"] == "p1"
    assert port["duplicate_links"] == [
        {"id": "p1", "source": "panther", "title": "IAM user created", "relation": "canonical"},
    ]

    canonical = (await client.get("/api/v1/detections/p1")).json()
    assert canonical["duplicate_of"] is None
    assert canonical["duplicate_links"] == [
        {"id": "py1", "source": "pypanther", "title": "IAM user created", "relation": "port"},
    ]

    solo = (await client.get("/api/v1/detections/py2")).json()
    assert solo["duplicate_of"] is None and solo["duplicate_links"] == []

    # The list keeps the id link (cheap) and omits the detail-only links;
    # the slim list drops null keys, so an unlinked row has no key at all.
    rows = (await client.get("/api/v1/detections?sources=pypanther&limit=10")).json()["items"]
    by_id = {r["id"]: r for r in rows}
    assert by_id["py1"]["duplicate_of"] == "p1" and by_id["py2"].get("duplicate_of") is None
    assert "duplicate_links" not in by_id["py1"]


@pytest.mark.asyncio
async def test_statistics_disclose_linked_ports_per_source(client, pair):
    stats = (await client.get("/api/v1/detections/statistics")).json()
    assert stats["ports"] == {"pypanther": 1}
    # Inside the total, not subtracted from it: the headline is "rules indexed".
    assert stats["total"] == 4 and stats["by_source"]["pypanther"] == 2


@pytest.mark.asyncio
async def test_linked_port_neither_gives_nor_gets_an_equivalent(client, pair):
    rows = (await client.get("/api/v1/detections?limit=50")).json()["items"]
    equiv = {r["id"]: r["equivalent_sources"] for r in rows}
    assert equiv["p1"] == ["elastic"], "the canonical pairs with elastic, not with its own port"
    assert equiv["e1"] == ["panther"], "elastic sees panther once, never pypanther through the port"
    assert equiv["py1"] == [], "the port stores no equivalents"
    # An unlinked port-source rule is an ordinary rule for the pass: it
    # shares nothing with the pair here, so it gets nothing.
    assert equiv["py2"] == []
