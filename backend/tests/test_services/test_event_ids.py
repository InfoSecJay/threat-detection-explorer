"""Per-event-ID taxonomy refinement (issue #16).

Two halves: integrity tripwires on `mappings/event_ids.yaml` (the
dictionary is looked up by number alone, so a duplicate ID across
providers would silently pick one meaning) and the semantics of
`refine_event_types`, which is the only place the "no inference from
channel-level logsources" rule of docs/taxonomy.md is lifted.
"""

from __future__ import annotations

import pytest

from app.normalizers.base import NormalizedDetection
from app.services.taxonomy.canonical import EVENT_TYPES
from app.services.taxonomy.event_ids import (
    COARSE_EVENT_TYPES,
    EVENT_ID_INDEX,
    _load,
    dictionary,
    labels_for,
    lookup,
    refine_event_types,
)

WIN = (["windows"], ["windows_security_event_log"])


# ── Dictionary integrity ──────────────────────────────────────────────────


def test_dictionary_loads_strictly():
    """Duplicates, non-canonical types and empty entries raise in strict
    mode -- the runtime loader only warns, so this is the real gate."""
    index = _load(strict=True)
    assert len(index) >= 200
    assert index.keys() == EVENT_ID_INDEX.keys()


def test_every_event_type_is_canonical_and_never_coarse():
    for entry in EVENT_ID_INDEX.values():
        assert entry.event_types, entry
        for t in entry.event_types:
            assert t in EVENT_TYPES, f"{entry.event_id}: {t!r} not canonical"
            assert t not in COARSE_EVENT_TYPES, f"{entry.event_id}: refines to a coarse type"


def test_ids_are_numeric_and_labels_ascii():
    for entry in EVENT_ID_INDEX.values():
        assert entry.event_id.isdigit(), entry.event_id
        assert entry.label and entry.label.isascii(), entry


def test_known_collisions_are_excluded():
    """8001-8004 mean NTLM audit in one channel and AppLocker EXE/DLL
    in another; without the channel we cannot tell them apart."""
    for eid in ("8001", "8002", "8003", "8004", "8005", "8006", "8007"):
        assert lookup(eid) is None, eid


@pytest.mark.parametrize(
    "eid, expected",
    [
        ("4624", ("authentication",)),
        ("4688", ("process_creation",)),
        ("4697", ("service_install",)),
        ("7045", ("service_install",)),
        ("4720", ("account_management",)),
        ("4728", ("account_management",)),
        ("4698", ("scheduled_task",)),
        ("1102", ("log_clear",)),
        ("5145", ("share_access",)),
        ("5136", ("directory_service_event",)),
        ("4104", ("process_creation",)),  # PowerShell convention, matches sigma.yaml
        ("1", ("process_creation",)),
        ("22", ("dns_query",)),
    ],
)
def test_spot_checks(eid, expected):
    assert lookup(eid).event_types == expected


def test_lookup_accepts_ints_and_whitespace():
    assert lookup(4624) is lookup(" 4624 ")


# ── refine_event_types semantics ──────────────────────────────────────────


def test_coarse_type_is_replaced_by_dictionary_types():
    assert refine_event_types(["audit_event"], *WIN, ["4624"]) == ["authentication"]
    assert refine_event_types(["unknown"], *WIN, ["4688"]) == ["process_creation"]


def test_multiple_ids_union_their_types():
    out = refine_event_types(["audit_event"], *WIN, ["4624", "4688", "4720"])
    assert out == ["account_management", "authentication", "process_creation"]


def test_specific_vendor_types_are_kept_and_unioned():
    # Splunk "Sysmon EventID 1 AND Windows Event Log Security 4663":
    # process_creation came from an explicit category and stays.
    out = refine_event_types(["process_creation"], *WIN, ["4663"])
    assert out == ["object_access", "process_creation"]


def test_unknown_id_keeps_audit_event_alongside_refinement():
    out = refine_event_types(["audit_event"], *WIN, ["4624", "99999"])
    assert out == ["audit_event", "authentication"]


def test_only_unknown_ids_change_nothing():
    assert refine_event_types(["audit_event"], *WIN, ["99999"]) == ["audit_event"]


def test_no_ids_is_a_no_op():
    assert refine_event_types(["audit_event"], *WIN, []) == ["audit_event"]
    assert refine_event_types(["audit_event"], *WIN, ["", " "]) == ["audit_event"]


def test_non_windows_rules_are_never_refined():
    # auditd `type=1`-style numerics must not pick up the Sysmon meaning.
    assert refine_event_types(["audit_event"], ["linux"], ["auditd"], ["1"]) == ["audit_event"]
    assert refine_event_types(["api_call"], ["aws"], ["cloudtrail"], ["4624"]) == ["api_call"]


def test_windows_data_source_alone_is_enough_scope():
    assert refine_event_types(["audit_event"], [], ["sysmon"], ["3"]) == ["network_connection"]


def test_result_is_sorted_and_deduplicated():
    out = refine_event_types(["authentication", "audit_event"], *WIN, ["4625", "4624"])
    assert out == ["authentication"]


# ── Wiring: NormalizedDetection applies it for every source ──────────────


def _normalized(**overrides) -> NormalizedDetection:
    base = dict(
        id="x",
        source="sentinel",
        source_file="f.yaml",
        source_repo_url="https://example.invalid",
        title="t",
        description=None,
        author=None,
        status="stable",
        severity="medium",
        platforms=["windows"],
        data_sources=["windows_security_event_log"],
        event_types=["audit_event"],
    )
    base.update(overrides)
    return NormalizedDetection(**base)


def test_normalized_detection_refines_on_construction():
    d = _normalized(extracted_event_ids=["4688"])
    assert d.event_types == ["process_creation"]


def test_normalized_detection_without_ids_is_untouched():
    d = _normalized()
    assert d.event_types == ["audit_event"]


def test_normalized_detection_keeps_sentinel_authentication_tag():
    # sentinel.yaml `securityevents` -> [authentication, audit_event]
    d = _normalized(event_types=["authentication", "audit_event"], extracted_event_ids=["4688"])
    assert d.event_types == ["authentication", "process_creation"]


# ── API surface helpers ───────────────────────────────────────────────────


def test_labels_for_and_dictionary_shape():
    assert labels_for(["4688", "nope"]) == {"4688": "Process created"}
    d = dictionary()
    assert d["4624"] == {
        "label": "Logon success",
        "provider": "windows_security",
        "channel": "Security",
        "event_types": ["authentication"],
    }
    assert list(d)[:3] == ["1", "2", "3"]  # numeric order, not lexical
