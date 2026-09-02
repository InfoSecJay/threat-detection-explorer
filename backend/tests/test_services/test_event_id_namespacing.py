"""Channel-namespaced event IDs (teardown R12 / #110).

`eventid:1` used to mean Sysmon ProcessCreate in one rule and a System
log event in another. Stored values now carry the channel
(`sysmon:1`, `security:4688`), decided from the rule's canonical data
source; a bare number remains a searchable alias for any channel.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.models.detection import Detection
from app.services.query_parser import parse_query
from app.services.search import SearchFilters, SearchService
from app.services.taxonomy.event_ids import (
    channel_for_prefix,
    lookup,
    namespace_event_ids,
    refine_event_types,
    split_event_id,
)


# ── split / lookup ────────────────────────────────────────────────────────


def test_split_only_on_known_prefixes():
    assert split_event_id("sysmon:1") == ("sysmon", "1")
    assert split_event_id("4688") == (None, "4688")
    # Vendor codes with a stray colon are not channel prefixes.
    assert split_event_id("foo:bar") == (None, "foo:bar")


def test_lookup_respects_the_channel():
    assert lookup("sysmon:1").label == lookup("1").label
    # Security-channel event 1 is NOT Sysmon ProcessCreate.
    assert lookup("security:1") is None
    assert lookup("security:4688").event_types == ("process_creation",)
    assert lookup("sysmon:4688") is None


def test_channel_for_prefix():
    assert channel_for_prefix("security") == "Security"
    assert "Sysmon" in channel_for_prefix("sysmon")
    assert channel_for_prefix("nope") is None


# ── namespace_event_ids ───────────────────────────────────────────────────


def test_single_windows_data_source_decides_the_channel():
    assert namespace_event_ids(["1", "3"], ["windows"], ["sysmon"]) == ["sysmon:1", "sysmon:3"]
    assert namespace_event_ids(["4688"], ["windows"], ["windows_security_event_log"]) == ["security:4688"]
    assert namespace_event_ids(["4104"], ["windows"], ["windows_powershell"]) == ["powershell:4104"]


def test_rule_channel_wins_over_the_dictionary():
    # A Security-channel rule that pins EventID 1 keeps its own channel,
    # even though the dictionary only knows 1 as Sysmon.
    assert namespace_event_ids(["1"], ["windows"], ["windows_security_event_log"]) == ["security:1"]


def test_ambiguous_or_generic_source_falls_back_to_dictionary():
    # Generic windows_event_logs, or two channels at once: per-ID lookup.
    assert namespace_event_ids(["4688", "1"], ["windows"], ["windows_event_logs"]) == ["security:4688", "sysmon:1"]
    assert namespace_event_ids(["4688", "1"], ["windows"], ["sysmon", "windows_security_event_log"]) == [
        "security:4688",
        "sysmon:1",
    ]
    # Unknown to the dictionary and no single channel: stays bare.
    assert namespace_event_ids(["99999"], ["windows"], ["windows_event_logs"]) == ["99999"]


def test_non_windows_rules_are_untouched():
    assert namespace_event_ids(["1", "f"], ["linux"], ["auditd"]) == ["1", "f"]
    assert namespace_event_ids(["fp", "s"], [], ["auth0_logs"]) == ["fp", "s"]


def test_idempotent_and_deduplicating():
    out = namespace_event_ids(["sysmon:1", "1", "1"], ["windows"], ["sysmon"])
    assert out == ["sysmon:1"]


def test_refinement_is_prefix_aware():
    win = (["windows"], ["windows_security_event_log"])
    assert refine_event_types(["audit_event"], *win, ["security:4688"]) == ["process_creation"]
    # security:1 is unknown -> nothing to refine with.
    assert refine_event_types(["audit_event"], *win, ["security:1"]) == ["audit_event"]


# ── search filter + query bar aliasing ───────────────────────────────────


def _rule(rid, event_ids):
    return Detection(
        id=rid, source="sigma", source_file=f"{rid}.yml",
        source_repo_url="https://example.com/repo.git", title=rid,
        detection_logic="x", raw_content="x", language="sigma",
        created_at=datetime(2026, 1, 1), updated_at=datetime(2026, 1, 1),
        extracted_event_ids=event_ids,
    )


@pytest.mark.asyncio
async def test_bare_number_matches_any_channel_and_legacy_values(db_session):
    db_session.add_all([
        _rule("sysmon", ["sysmon:1"]),
        _rule("system", ["system:1"]),
        _rule("legacy", ["1"]),
        _rule("other", ["security:4688", "sysmon:11"]),
    ])
    await db_session.commit()
    svc = SearchService(db_session)

    async def ids(**kw):
        rows, _total = await svc.search_detections(SearchFilters(**kw))
        return sorted(d.id for d in rows)

    assert await ids(event_ids=["1"]) == ["legacy", "sysmon", "system"]
    assert await ids(event_ids=["sysmon:1"]) == ["sysmon"]
    assert await ids(event_ids=["system:1"]) == ["system"]
    assert await ids(event_ids=["4688"]) == ["other"]


def _sql(clause) -> str:
    return str(clause.compile(compile_kwargs={"literal_binds": True})).lower()


def test_query_bar_accepts_namespaced_and_bare_forms():
    s = _sql(parse_query("eventid:sysmon:1"))
    assert '\'%"sysmon:1"%\'' in s
    assert '\'%"1"%\'' not in s

    s = _sql(parse_query('eventid:"security:4688"'))
    assert '\'%"security:4688"%\'' in s

    s = _sql(parse_query("eventid:4688"))
    assert '\'%"4688"%\'' in s and "'%:4688\"%'" in s
