"""#139: the documented filter names (data_sources=, event_types=) work on
the list, facets and export surfaces, and the legacy names remain as
deprecated aliases. Unknown query parameters are ignored by FastAPI, so
the documented name must exist in the spec or a caller gets the
unfiltered set with a 200."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from app.api import schemas
from app.api.routes.detections import _first
from app.database import get_db
from app.main import app


@pytest_asyncio.fixture
async def client(db_session):
    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


def _params(path: str) -> dict[str, dict]:
    spec = app.openapi()
    return {p["name"]: p for p in spec["paths"][path]["get"]["parameters"]}


@pytest.mark.parametrize("path", ["/api/v1/detections", "/api/v1/detections/facets"])
def test_documented_names_are_in_the_spec_and_legacy_ones_are_deprecated(path):
    params = _params(path)
    assert "data_sources" in params and "event_types" in params
    assert not params["data_sources"].get("deprecated")
    assert params["data_sources_normalized"].get("deprecated") is True
    assert params["event_categories"].get("deprecated") is True


def test_documented_name_wins_over_its_alias():
    assert _first("a", "b") == "a"
    assert _first(None, "b") == "b"
    assert _first("", "b") == "b"
    assert _first(None, None) is None


def test_body_filters_accept_the_documented_names():
    cls = next(
        c for c in vars(schemas).values()
        if isinstance(c, type) and issubclass(c, BaseModel) and "data_sources_normalized" in c.model_fields
    )
    f = cls(event_types=["process_creation"], data_sources=["sysmon"])
    assert f.event_categories == ["process_creation"]
    assert f.data_sources_normalized == ["sysmon"]
    legacy = cls(event_categories=["file_event"], data_sources_normalized=["auditd"])
    assert legacy.event_categories == ["file_event"] and legacy.data_sources_normalized == ["auditd"]


@pytest.mark.asyncio
async def test_both_spellings_answer_the_same(client):
    a = await client.get("/api/v1/detections?data_sources=sysmon&event_types=process_creation&limit=5")
    b = await client.get("/api/v1/detections?data_sources_normalized=sysmon&event_categories=process_creation&limit=5")
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()
    fa = await client.get("/api/v1/detections/facets?data_sources=sysmon")
    fb = await client.get("/api/v1/detections/facets?data_sources_normalized=sysmon")
    assert fa.status_code == fb.status_code == 200
    assert fa.json() == fb.json()
