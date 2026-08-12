"""Tests for the MISP-galaxy actor context enrichment.

Covers the normalization tables (motivations, sectors, regions), the
alias-based join incl. ambiguity handling, and — against the real
vendored galaxy + ATT&CK catalog — the Phase 1 acceptance criteria:
>=60% of actors get an origin country, and GOLD SAHARA / PUNK SPIDER /
Howling Scorpius all resolve to Akira/G1024.
"""

import json
import logging

import pytest

from app.services.actor_context import (
    ActorContextService,
    AMBIGUITY_OVERRIDES,
    VENDORED_FILE,
    actor_context_service,
    merge_aliases,
    normalize_alias,
    normalize_motivations,
    normalize_sectors,
    rollup_regions,
)
from app.services.mitre import CACHE_FILE, mitre_service


# ── Normalization ──────────────────────────────────────────────────

def test_normalize_alias_strips_case_and_punctuation():
    assert normalize_alias("GOLD SAHARA") == "goldsahara"
    assert normalize_alias("gold-sahara") == "goldsahara"
    assert normalize_alias("APT-29") == normalize_alias("APT 29") == "apt29"
    assert normalize_alias("TEMP.Periscope") == "tempperiscope"


def test_normalize_motivations_maps_cfr_and_motive():
    meta = {
        "cfr-type-of-incident": ["Espionage", "Denial of service"],
        "motive": "Cybercrime",
    }
    assert normalize_motivations(meta) == ["espionage", "destructive", "financial-crime"]


def test_normalize_motivations_free_text_keywords():
    meta = {"motive": "mainly financially motivated, additional espionage objective."}
    # Order follows the keyword table, not text position.
    assert normalize_motivations(meta) == ["espionage", "financial-crime"]


def test_normalize_motivations_ransomware_from_description():
    got = normalize_motivations({}, "Operator of the Akira Ransomware-as-a-Service.")
    assert got == ["ransomware"]
    # Word boundary: no substring trap on 'ransomwareish' nonsense.
    assert normalize_motivations({}, "totally benign text") == []


def test_normalize_sectors_canonicalizes_telecom_variants():
    meta = {"cfr-target-category": ["Telecomms", "Telecoms", "Telecommunications", "High-Tech"]}
    assert normalize_sectors(meta) == ["telecommunications", "technology"]


def test_rollup_regions():
    got = rollup_regions(["United States", "Germany", "Taiwan", "Narnia", "Middle East"])
    assert got == ["north-america", "europe", "east-asia", "middle-east"]


def test_merge_aliases_dedupes_normalized_and_excludes_primary():
    ctx = {"galaxy_aliases": ["Akira", "PUNK SPIDER", "Gold-Sahara", "Storm-1567"]}
    got = merge_aliases(["Howling Scorpius", "GOLD SAHARA"], ctx, exclude="Akira")
    assert got == ["Howling Scorpius", "GOLD SAHARA", "PUNK SPIDER", "Storm-1567"]


# ── Join behavior (synthetic clusters) ─────────────────────────────

SYN_CLUSTERS = [
    {
        "uuid": "u-alpha",
        "value": "AlphaBear",
        "description": "Espionage crew.",
        "meta": {
            "country": "RU",
            "synonyms": ["Alpha Bear", "STONE ALPHA"],
            "cfr-type-of-incident": ["Espionage"],
            "cfr-target-category": ["Government"],
            "cfr-suspected-victims": ["United States", "Germany"],
            "refs": ["https://example.com/alpha"],
        },
    },
    {
        "uuid": "u-beta1",
        "value": "BetaCrew",
        "meta": {"synonyms": ["Beta Group"], "country": "CN"},
    },
    {
        "uuid": "u-beta2",
        "value": "Beta Collective",
        "meta": {"synonyms": ["BetaCrew"], "country": "KP"},
    },
]

SYN_GROUPS = {
    "G9001": {"id": "G9001", "name": "Alpha Group", "aliases": ["Stone Alpha"]},
    # Alias hits BOTH beta clusters (value of one, synonym of the
    # other) -> ambiguous.
    "G9002": {"id": "G9002", "name": "Beta Group", "aliases": ["BetaCrew"]},
    "G9003": {"id": "G9003", "name": "Unmatched Group", "aliases": []},
}


def _service_with(clusters):
    svc = ActorContextService()
    svc._clusters = clusters
    svc._version = 1
    svc._loaded = True
    return svc


def test_join_matches_on_alias_not_name():
    svc = _service_with(SYN_CLUSTERS)
    svc._join(SYN_GROUPS)
    # 'Alpha Group' != 'AlphaBear' by name, but alias 'Stone Alpha'
    # matches synonym 'STONE ALPHA' after normalization.
    ctx = svc.get_context("G9001")
    assert ctx is not None
    assert ctx["origin_country"] == "RU"
    assert ctx["motivations"] == ["espionage"]
    assert ctx["target_sectors"] == ["government"]
    assert ctx["target_regions"] == ["north-america", "europe"]
    assert ctx["references"] == ["https://example.com/alpha"]
    # Unmatched actor gets nothing, not an empty shell.
    assert svc.get_context("G9003") is None


def test_join_ambiguity_is_skipped_and_logged(caplog):
    svc = _service_with(SYN_CLUSTERS)
    # 'Beta Group' matches both beta clusters (synonym + value).
    with caplog.at_level(logging.WARNING):
        svc._join(SYN_GROUPS)
    assert svc.get_context("G9002") is None
    assert any("ambiguous" in r.message for r in caplog.records)


def test_join_ambiguity_override_resolves(monkeypatch):
    svc = _service_with(SYN_CLUSTERS)
    monkeypatch.setitem(AMBIGUITY_OVERRIDES, "G9002", "u-beta2")
    svc._join(SYN_GROUPS)
    ctx = svc.get_context("G9002")
    assert ctx is not None and ctx["origin_country"] == "KP"


def test_alias_index_includes_galaxy_synonyms():
    svc = _service_with(SYN_CLUSTERS)
    svc._join(SYN_GROUPS)
    assert svc.resolve_alias("STONE ALPHA") == ["G9001"]
    assert svc.resolve_alias("AlphaBear") == ["G9001"]   # cluster value
    assert svc.resolve_alias("alpha group") == ["G9001"]  # ATT&CK name
    assert svc.resolve_alias("nobody") == []


# ── Acceptance against real data ───────────────────────────────────

@pytest.mark.skipif(
    not (VENDORED_FILE.exists() and CACHE_FILE.exists()),
    reason="needs vendored galaxy + real ATT&CK catalog cache",
)
def test_acceptance_real_join(monkeypatch):
    attack = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    if not attack.get("groups"):
        pytest.skip("catalog cache predates groups payload")
    monkeypatch.setattr(mitre_service, "_groups", attack["groups"])
    monkeypatch.setattr(mitre_service, "_techniques", attack["techniques"])
    monkeypatch.setattr(mitre_service, "_loaded", True)

    galaxy = json.loads(VENDORED_FILE.read_text(encoding="utf-8"))
    svc = _service_with(galaxy["values"])
    svc._join(attack["groups"])

    groups = attack["groups"]
    with_origin = sum(
        1 for c in svc.all_contexts().values() if c["origin_country"]
    )
    assert with_origin / len(groups) >= 0.60, (
        f"only {with_origin}/{len(groups)} actors have origin_country"
    )

    # Alias index resolves all three Akira names to G1024.
    for alias in ("GOLD SAHARA", "PUNK SPIDER", "Howling Scorpius"):
        assert svc.resolve_alias(alias) == ["G1024"], alias

    # Tripwire: every current ambiguity must be covered by an
    # override. When the galaxy adds clusters that re-ambiguate an
    # actor, this fails and the override map needs a new entry.
    import logging as _logging
    records: list[str] = []

    class _Capture(_logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Capture()
    _logging.getLogger("app.services.actor_context").addHandler(handler)
    try:
        svc2 = _service_with(galaxy["values"])
        svc2._join(attack["groups"])
    finally:
        _logging.getLogger("app.services.actor_context").removeHandler(handler)
    ambiguous_msgs = [m for m in records if "ambiguous matches skipped" in m]
    assert not ambiguous_msgs, "unresolved galaxy ambiguities:\n" + "\n".join(ambiguous_msgs)
