"""Elastic `note` (markdown investigation guide) reaches the API."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.normalizers.elastic import _guide_text


def test_guide_text_joins_note_and_setup():
    assert _guide_text("## Triage\n\nCheck the user.", None) == "## Triage\n\nCheck the user."
    assert _guide_text(" ", "Enable the integration.") == "## Setup\n\nEnable the integration."
    assert _guide_text("Note", "Setup") == "Note\n\n## Setup\n\nSetup"
    assert _guide_text(None, None) is None


@pytest.mark.asyncio
async def test_detail_response_carries_the_guide(db_session):
    db_session.add(Detection(
        id="elastic:g", source="elastic", source_file="r.toml", source_repo_url="https://x", title="Guided",
        detection_logic="x", language="kql", raw_content="raw", severity="high", status="stable",
        investigation_guide="## Investigating\n\n- Check `event.action`",
    ))
    db_session.add(Detection(
        id="sigma:n", source="sigma", source_file="r.yml", source_repo_url="https://x", title="Plain",
        detection_logic="x", language="sigma", raw_content="raw", severity="low", status="stable",
    ))
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            guided = (await c.get("/api/detections/elastic:g")).json()
            plain = (await c.get("/api/detections/sigma:n")).json()
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert guided["investigation_guide"].startswith("## Investigating")
    assert plain["investigation_guide"] is None
