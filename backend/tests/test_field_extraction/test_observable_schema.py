"""Schema-drift tripwire for the observable vocabulary (issue #6).

The extracted_observables `type` / `subtype` vocabulary is pinned in
taxonomy/canonical.py. The extractor must only emit pinned pairs —
adding a new mapping to FIELD_TYPE_MAP (or a new heuristic fallback)
without adding the pair to the canonical vocabulary is exactly the
uncontrolled drift that made the original schema "loose" in the first
place.
"""

import re

from app.services.field_extractor import FIELD_TYPE_MAP, _classify_field
from app.services.taxonomy.canonical import (
    OBSERVABLE_SUBTYPES,
    OBSERVABLE_TYPES,
    is_valid_observable,
    is_valid_observable_type,
)


def test_every_field_type_map_pair_is_pinned():
    unpinned = sorted(
        {
            (t, st)
            for t, st in FIELD_TYPE_MAP.values()
            if not is_valid_observable(t, st)
        }
    )
    assert not unpinned, (
        f"FIELD_TYPE_MAP emits pairs missing from canonical "
        f"OBSERVABLE_SUBTYPES: {unpinned} — add them to canonical.py "
        f"deliberately or fix the mapping"
    )


def test_heuristic_fallback_pairs_are_pinned():
    # One representative unmapped field name per fallback branch of
    # _classify_field, plus the last-resort branch.
    for name in (
        "somecustomprocessfield",   # -> (process, process_field)
        "regcustomthing",           # -> (registry, registry_field)
        "custompathvalue",          # -> (file, file_field)
        "operationnamevalue",       # -> (cloud, api_action)
        "sendercustom",             # -> (email, email_field)
        "dnscustom",                # -> (dns, dns_field)
        "actorcustom",              # -> (identity, identity_field)
        "arncustom",                # -> (cloud, resource)
        "hostcustom",               # -> (network, network_field)
        "logoncustom",              # -> (authentication, auth_field)
        "zzz",                      # -> (other, unknown)
    ):
        t, st = _classify_field(name)
        assert is_valid_observable(t, st), (name, t, st)


def test_subtype_map_types_match_type_set():
    assert set(OBSERVABLE_SUBTYPES) == set(OBSERVABLE_TYPES)


def test_vocabulary_naming_convention():
    # lowercase_snake_case, same convention as the rest of canonical.py.
    ident = re.compile(r"^[a-z][a-z0-9_]*$")
    for t in OBSERVABLE_TYPES:
        assert ident.match(t), t
    for t, subs in OBSERVABLE_SUBTYPES.items():
        for st in subs:
            assert ident.match(st), (t, st)


def test_validators():
    assert is_valid_observable_type("process")
    assert not is_valid_observable_type("prozess")
    assert is_valid_observable("process", "process_name")
    assert not is_valid_observable("process", "registry_key")
    assert not is_valid_observable("nonsense", "process_name")
