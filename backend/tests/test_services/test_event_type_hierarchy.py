"""Event-type hierarchy (#104 / teardown R06, B5).

Stored values stay leaves; a parent map on top makes the filter expand
a parent to its children and the facet nest children under parents.
"""

from __future__ import annotations

import pytest
from sqlalchemy import and_, select

from app.models.detection import Detection
from app.services.search import SearchFilters, SearchService
from app.services.taxonomy.canonical import (
    EVENT_TYPE_GROUPS,
    EVENT_TYPE_PARENTS,
    EVENT_TYPES,
    event_type_children,
    event_type_parent,
    expand_event_types,
    is_event_type_parent,
)


def _rule(i: int, event_types: list[str], source: str = "sigma") -> Detection:
    return Detection(
        id=f"{source}-{i}", source=source, source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i}", detection_logic="x", language="sigma", raw_content="x",
        severity="high", status="stable", platforms=["windows"], data_sources=["sysmon"],
        event_types=event_types, mitre_techniques=["T1059"],
    )


def test_every_child_is_a_canonical_leaf_and_belongs_to_one_parent():
    seen: dict[str, str] = {}
    for parent, children in EVENT_TYPE_GROUPS.items():
        for c in children:
            assert c in EVENT_TYPES, c
            assert c not in seen, f"{c} listed under {seen[c]} and {parent}"
            seen[c] = parent
    # Sigma generic categories are both a storable leaf and a parent.
    for generic in ("file_event", "registry_event", "audit_event"):
        assert generic in EVENT_TYPES and is_event_type_parent(generic)
    # Grouping-only parents are never storable values.
    for grouping in ("process_event", "powershell_event", "network_event", "sensor_event"):
        assert grouping not in EVENT_TYPES and is_event_type_parent(grouping)


def test_parent_child_lookups():
    assert event_type_parent("file_delete") == "file_event"
    assert event_type_parent("ps_script") == "powershell_event"
    assert event_type_parent("authentication") is None
    assert event_type_parent("file_event") is None  # parents have no parent
    assert "registry_set" in event_type_children("registry_event")
    assert event_type_children("authentication") == ()
    assert EVENT_TYPE_PARENTS["dns_query"] == "network_event"


def test_expand_is_stable_and_deduplicated():
    assert expand_event_types(["authentication"]) == ["authentication"]
    assert expand_event_types(["registry_event"]) == [
        "registry_event", "registry_set", "registry_add", "registry_delete", "registry_rename",
    ]
    # A child listed alongside its parent is not duplicated; order preserved.
    assert expand_event_types(["registry_set", "registry_event"])[:2] == ["registry_set", "registry_event"]
    assert len(expand_event_types(["registry_set", "registry_event"])) == 5
    assert expand_event_types([]) == [] and expand_event_types(None) == []
    assert expand_event_types(["unknown", 3]) == ["unknown"]


@pytest.mark.asyncio
async def test_filtering_a_parent_includes_its_children(db_session):
    db_session.add_all([
        _rule(1, ["file_event"]),
        _rule(2, ["file_delete"]),
        _rule(3, ["registry_set"]),
        _rule(4, ["process_creation", "file_change"]),
        _rule(5, ["authentication"]),
    ])
    await db_session.commit()
    svc = SearchService(db_session)

    async def ids(**kw):
        conds = svc._build_conditions(SearchFilters(**kw))
        rows = await db_session.execute(select(Detection.id).where(and_(*conds)))
        return sorted(r[0] for r in rows)

    assert await ids(event_categories=["file_event"]) == ["sigma-1", "sigma-2", "sigma-4"]
    assert await ids(event_categories=["file_delete"]) == ["sigma-2"]
    assert await ids(event_categories=["process_event"]) == ["sigma-4"]
    assert await ids(event_categories=["registry_event", "authentication"]) == ["sigma-3", "sigma-5"]


@pytest.mark.asyncio
async def test_facets_nest_children_with_union_counts(db_session):
    db_session.add_all([
        _rule(1, ["file_event"]),
        _rule(2, ["file_delete"]),
        _rule(3, ["file_delete", "file_change"]),  # one rule, two file kinds
        _rule(4, ["process_creation"]),
        _rule(5, ["authentication"]),
        _rule(6, ["unknown"]),
    ])
    await db_session.commit()
    facets = await SearchService(db_session).get_facets(SearchFilters())

    # Flat leaves unchanged for older clients.
    flat = {f["value"]: f["count"] for f in facets["event_types"]}
    assert flat["file_delete"] == 2 and flat["file_event"] == 1 and flat["file_change"] == 1

    groups = {g["value"]: g for g in facets["event_type_groups"]}
    # file_event: rules 1, 2, 3 -> 3 distinct rules, not 1 + 2 + 1.
    assert groups["file_event"]["count"] == 3
    assert [c["value"] for c in groups["file_event"]["children"]] == ["file_delete", "file_change"]
    assert groups["process_event"]["count"] == 1
    assert groups["process_event"]["children"] == [{"value": "process_creation", "count": 1}]
    # Leaves without a parent are childless groups; parents with nothing under them are absent.
    assert groups["authentication"] == {"value": "authentication", "count": 1, "children": []}
    assert "registry_event" not in groups and "network_event" not in groups
    # Children never appear as top-level groups.
    assert "file_delete" not in groups
    # unknown sorts last regardless of count.
    assert facets["event_type_groups"][-1]["value"] == "unknown"


@pytest.mark.asyncio
async def test_persisted_facets_key_carries_the_shape_version(db_session, monkeypatch):
    """The default facet set persists across deploys keyed on the corpus
    fingerprint (#81); a change to the response SHAPE (event_type_groups)
    must invalidate it or prod serves the old shape until the next sync."""
    from app.services import search as search_module

    captured: dict = {}

    async def fake_get(db, key, compute, persist=False):
        captured["key"] = key
        captured["persist"] = persist
        return await compute()

    monkeypatch.setattr(search_module.corpus_cache, "get", fake_get)
    await SearchService(db_session).get_facets(SearchFilters())
    assert captured["persist"] is True
    assert captured["key"][0] == "facets"
    assert captured["key"][1].startswith(f"v{search_module._FACETS_SHAPE_VERSION}:")


def test_query_bar_event_field_expands_parents():
    from app.services.query_parser import parse_query

    def sql(q: str) -> str:
        clause = parse_query(q)
        assert clause is not None
        return str(clause.compile(compile_kwargs={"literal_binds": True}))

    parent = sql("event:file_event")
    assert '"file_event"' in parent and '"file_delete"' in parent and '"create_stream_hash"' in parent
    leaf = sql("event:file_delete")
    assert '"file_delete"' in leaf and '"file_event"' not in leaf
    grouping_only = sql("event:process_event")
    assert '"process_creation"' in grouping_only and '"image_load"' in grouping_only
