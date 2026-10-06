"""DX-10 / #166: the nightly duplicate_of pass that links a PyPanther port
to its panther-analysis twin, and what the link means for coverage."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.services.coverage_scope import (
    DEFAULT_SCOPE,
    PORT_SOURCES,
    CoverageScope,
    coverage_conditions,
    duplicate_conditions,
    is_hidden_duplicate,
    parse_scope,
)
from app.services.duplicates import (
    PORT_ID_SUFFIXES,
    canonical_rule_id,
    compute_duplicate_links,
    write_duplicate_links,
)


def _rule(id_: str, source: str, rule_id: str | None, **kw) -> Detection:
    base = dict(
        id=id_, source=source, rule_id=rule_id, source_file=f"{source}/{id_}.py",
        source_repo_url="https://example.test", title=id_, description="", severity="high",
        status="stable", language="python", detection_logic="x", raw_content="x",
    )
    base.update(kw)
    return Detection(**base)


def test_every_port_source_has_a_canonical_and_a_suffix():
    assert set(PORT_ID_SUFFIXES) == set(PORT_SOURCES)
    for port, canonical in PORT_SOURCES.items():
        assert canonical not in PORT_SOURCES, "a canonical source cannot itself be a port"


def test_canonical_rule_id_strips_the_suffix_for_port_sources_only():
    assert canonical_rule_id("pypanther", "AWS.CloudTrail.Stopped-prototype") == "AWS.CloudTrail.Stopped"
    assert canonical_rule_id("pypanther", "AWS.CloudTrail.Stopped") is None
    assert canonical_rule_id("pypanther", "-prototype") is None
    assert canonical_rule_id("pypanther", None) is None
    assert canonical_rule_id("panther", "AWS.CloudTrail.Stopped-prototype") is None
    assert canonical_rule_id("sigma", "anything-prototype") is None


def test_compute_links_pairs_on_the_stem_and_never_guesses():
    rows = [
        ("p1", "panther", "AWS.One"),
        ("p2", "panther", "AWS.Two"),
        ("p3a", "panther", "AWS.Three"),
        ("p3b", "panther", "AWS.Three"),       # ambiguous canonical id
        ("py1", "pypanther", "AWS.One-prototype"),
        ("py3", "pypanther", "AWS.Three-prototype"),
        ("py4", "pypanther", "AWS.Four-prototype"),  # no twin
        ("py5", "pypanther", "AWS.Two"),             # no suffix
        ("s1", "sigma", "AWS.One-prototype"),        # not a port source
    ]
    links = compute_duplicate_links(rows)
    assert links == {"py1": "p1", "py3": None, "py4": None, "py5": None}
    assert "s1" not in links and "p1" not in links


@pytest.mark.asyncio
async def test_write_links_sets_clears_and_reports(db_session):
    db_session.add_all([
        _rule("p1", "panther", "AWS.One"),
        _rule("py1", "pypanther", "AWS.One-prototype"),
        _rule("py2", "pypanther", "AWS.Gone-prototype", duplicate_of="stale-id"),
        _rule("s1", "sigma", "whatever", duplicate_of="never-touched"),
    ])
    await db_session.commit()
    synced_before = dict((await db_session.execute(select(Detection.id, Detection.updated_at))).all())

    stats = await write_duplicate_links(db_session)
    assert (stats["ports"], stats["linked"], stats["unlinked"], stats["updated"]) == (2, 1, 1, 2)

    rows = dict((await db_session.execute(select(Detection.id, Detection.duplicate_of))).all())
    assert rows["py1"] == "p1"
    assert rows["py2"] is None, "a link whose twin is gone is cleared"
    assert rows["p1"] is None
    assert rows["s1"] == "never-touched", "non-port sources are not the pass's business"
    # Changed rows move the corpus fingerprint (max(updated_at)); the rest do not.
    synced_after = dict((await db_session.execute(select(Detection.id, Detection.updated_at))).all())
    assert synced_after["py1"] > synced_before["py1"] and synced_after["py2"] > synced_before["py2"]
    assert synced_after["p1"] == synced_before["p1"] and synced_after["s1"] == synced_before["s1"]

    # Idempotent: a second run writes nothing.
    again = await write_duplicate_links(db_session)
    assert again["updated"] == 0


def test_scope_hides_a_port_only_while_its_canonical_is_in_scope():
    assert DEFAULT_SCOPE.hides_source("pypanther")
    assert not DEFAULT_SCOPE.hides_source("panther")
    assert not DEFAULT_SCOPE.hides_source("sigma")
    assert not DEFAULT_SCOPE.counts_source("pypanther") and DEFAULT_SCOPE.counts_source("panther")

    both = parse_scope("panther,pypanther", "strict")
    assert both.hides_source("pypanther") and not both.counts_source("pypanther")

    port_only = parse_scope("pypanther,sigma", "strict")
    assert not port_only.hides_source("pypanther") and port_only.counts_source("pypanther")
    assert not port_only.counts_source("panther"), "out of scope, not hidden"


def test_is_hidden_duplicate_needs_a_link_and_a_canonical_in_scope():
    assert is_hidden_duplicate("pypanther", "p1")
    assert is_hidden_duplicate("pypanther", "p1", DEFAULT_SCOPE)
    assert not is_hidden_duplicate("pypanther", None)
    assert not is_hidden_duplicate("pypanther", "p1", CoverageScope(sources=frozenset({"pypanther"})))
    assert not is_hidden_duplicate("panther", "p1"), "only port sources hide"


def test_duplicate_conditions_render_and_vanish_with_the_canonical_out_of_scope():
    rendered = " ".join(str(c) for c in duplicate_conditions())
    assert "detections.duplicate_of IS NULL" in rendered
    assert "detections.source NOT IN" in rendered
    assert duplicate_conditions(CoverageScope(sources=frozenset({"pypanther"}))) == []
    # coverage_conditions carries the clause under the default scope.
    assert "duplicate_of IS NULL" in " ".join(str(c) for c in coverage_conditions())
