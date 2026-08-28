"""Observables v2: the extracted-observable dimensions are faceted."""

from datetime import datetime

import pytest

from app.models.detection import Detection
from app.services.search import SearchFilters, SearchService


def _rule(rid, source, **extracted):
    return Detection(
        id=rid, source=source, source_file=f"{rid}.yml",
        source_repo_url="https://example.com/repo.git", title=rid,
        detection_logic="x", raw_content="x", language="sigma",
        created_at=datetime(2026, 1, 1), updated_at=datetime(2026, 1, 1),
        **extracted,
    )


@pytest.mark.asyncio
async def test_observable_facets_count_per_rule(db_session):
    db_session.add_all([
        _rule("r1", "sigma", extracted_process_names=["powershell.exe", "cmd.exe"],
              extracted_event_ids=["4688"], extracted_source_tables=["SecurityEvent"]),
        _rule("r2", "sigma", extracted_process_names=["powershell.exe"],
              extracted_api_actions=["CreateUser"]),
        _rule("r3", "splunk", extracted_process_names=["powershell.exe"]),
    ])
    await db_session.commit()

    facets = await SearchService(db_session).get_facets(SearchFilters())
    for key in ("process_names", "api_actions", "source_tables", "event_ids"):
        assert key in facets, key
    assert facets["process_names"][0] == {"value": "powershell.exe", "count": 3}
    assert {"value": "cmd.exe", "count": 1} in facets["process_names"]
    assert facets["api_actions"] == [{"value": "CreateUser", "count": 1}]
    assert facets["event_ids"] == [{"value": "4688", "count": 1}]


@pytest.mark.asyncio
async def test_observable_facet_excludes_its_own_selection(db_session):
    db_session.add_all([
        _rule("r1", "sigma", extracted_process_names=["powershell.exe"]),
        _rule("r2", "sigma", extracted_process_names=["cmd.exe"]),
    ])
    await db_session.commit()

    # With process_names=cmd.exe applied, the process facet still offers
    # powershell.exe (standard multi-select semantics).
    facets = await SearchService(db_session).get_facets(
        SearchFilters(process_names=["cmd.exe"])
    )
    values = {f["value"] for f in facets["process_names"]}
    assert values == {"powershell.exe", "cmd.exe"}
