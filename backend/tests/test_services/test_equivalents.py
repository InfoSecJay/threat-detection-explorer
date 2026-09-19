"""DX-07 / #149: the nightly equivalent_sources pass and the filters,
facet and query field built on it."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.services.equivalents import compute_equivalent_sources, write_equivalent_sources
from app.services.search import SearchFilters, SearchService


def _rule(id_: str, source: str, *, techniques=(), procs=(), regs=(), status="stable") -> Detection:
    return Detection(
        id=id_, source=source, source_file=f"{source}/{id_}.yml", source_repo_url="https://example.test",
        title=id_, description="", severity="high", status=status, language="sigma",
        detection_logic="x", raw_content="x", mitre_tactics=[], mitre_techniques=list(techniques),
        tags=[], platforms=[], event_types=[], data_sources=[],
        extracted_event_ids=[], extracted_process_names=list(procs), extracted_registry_keys=list(regs),
        extracted_api_actions=[], extracted_file_paths=[], extracted_network_indicators=[],
    )


@pytest.fixture
async def corpus(db_session):
    rows = [
        # a/b share rundll32 + T1055 -> equivalent. c shares two
        # observables with a (no technique) -> equivalent with a, not b.
        _rule("a", "sigma", techniques=["T1055"], procs=["rundll32.exe"], regs=["HKCU\\Run"]),
        _rule("b", "elastic", techniques=["T1055"], procs=["rundll32.exe"]),
        _rule("c", "splunk", procs=["rundll32.exe"], regs=["hkcu\\run"]),
        # Deprecated: neither gives nor gets an equivalent (#109).
        _rule("d", "sentinel", techniques=["T1055"], procs=["rundll32.exe"], status="deprecated"),
        # powershell.exe is carried by five rules: over the generic cap,
        # so a shared technique plus that one process pairs nobody.
        _rule("e", "sigma", techniques=["T1059"], procs=["powershell.exe"]),
        _rule("f", "elastic", techniques=["T1059"], procs=["powershell.exe"]),
        _rule("g", "splunk", techniques=["T1059"], procs=["powershell.exe"]),
        _rule("h", "sigma", techniques=["T1059"], procs=["powershell.exe"]),
        _rule("i", "elastic", techniques=["T1059"], procs=["powershell.exe"]),
    ]
    db_session.add_all(rows)
    await db_session.commit()
    return rows


def test_compute_requires_an_observable_plus_technique_or_a_second_observable():
    rows = [
        ("a", "sigma", "stable", ["T1055"], ["rundll32.exe"], ["HKCU\\Run"], [], [], [], []),
        ("b", "elastic", "stable", ["T1055"], ["rundll32.exe"], [], [], [], [], []),
        ("c", "splunk", "stable", [], ["rundll32.exe"], ["hkcu\\run"], [], [], [], []),
        ("d", "sentinel", "deprecated", ["T1055"], ["rundll32.exe"], [], [], [], [], []),
        # Technique only, no observable: never equivalent (DX-02).
        ("t", "elastic", "stable", ["T1055"], [], [], [], [], [], []),
    ]
    out = compute_equivalent_sources(rows, generic_min=10)
    assert out["a"] == ["elastic", "splunk"]
    assert out["b"] == ["sigma"]  # one shared observable + technique with a; only one with c, no technique
    assert out["c"] == ["sigma"]
    assert out["t"] == []
    assert "d" not in out


def test_generic_values_never_pair_on_their_own():
    rows = [(f"r{i}", src, "stable", ["T1059"], ["powershell.exe"], [], [], [], [], [])
            for i, src in enumerate(["sigma", "elastic", "splunk", "sigma", "elastic"])]
    assert all(v == [] for v in compute_equivalent_sources(rows, generic_min=4).values())
    # Under the cap the same rows pair (technique + one observable);
    # same-source siblings count too (r3 is also sigma).
    assert compute_equivalent_sources(rows, generic_min=5)["r0"] == ["elastic", "sigma", "splunk"]


@pytest.mark.asyncio
async def test_write_pass_persists_and_is_idempotent(db_session, corpus):
    stats = await write_equivalent_sources(db_session, generic_min=4)
    assert stats["rules"] == 9 and stats["with_equivalent"] == 3
    assert stats["updated"] == 3  # a, b, c changed from []; the rest stayed []
    db_session.expire_all()  # the fixture's instances predate the Core UPDATE
    got = {r.id: r.equivalent_sources for r in (await db_session.execute(select(Detection))).scalars()}
    assert got["a"] == ["elastic", "splunk"] and got["b"] == ["sigma"] and got["c"] == ["sigma"]
    assert got["d"] == [] and got["e"] == []
    again = await write_equivalent_sources(db_session, generic_min=4)
    assert again["updated"] == 0


@pytest.mark.asyncio
async def test_filters_facet_and_query_field(db_session, corpus):
    await write_equivalent_sources(db_session, generic_min=4)
    search = SearchService(db_session)

    items, total = await search.search_detections(SearchFilters(equivalent_in=["elastic"]))
    assert {d.id for d in items} == {"a"}

    # The porting question: Sigma rules with no Elastic equivalent.
    items, _ = await search.search_detections(SearchFilters(sources=["sigma"], no_equivalent_in=["elastic"]))
    assert {d.id for d in items} == {"e", "h"}

    # Same answer through the query bar.
    items, _ = await search.search_detections(SearchFilters(q="source:sigma -equiv:elastic"))
    assert {d.id for d in items} == {"e", "h"}
    items, _ = await search.search_detections(SearchFilters(q="equiv:sigma"))
    assert {d.id for d in items} == {"b", "c"}

    facets = await search.get_facets(SearchFilters())
    assert facets["equivalent_sources"] == [
        {"value": "sigma", "count": 2}, {"value": "elastic", "count": 1}, {"value": "splunk", "count": 1},
    ]
