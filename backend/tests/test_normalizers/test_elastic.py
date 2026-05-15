"""Per-vendor normalizer tests for ElasticNormalizer.

Same shape as test_sigma.py — see that file's module docstring for
the rationale. Elastic-specific things to pin:
  - detection_logic_raw is a dict ``{type, query, language}``
  - language switches between eql/esql/kql/lucene based on rule.type
    + rule.language
  - tags get lowercased and spaces → underscores
  - data_sources are extracted from the index patterns
  - dates come from metadata.creation_date / metadata.updated_date
  - the metadata.promotion flag is preserved for the taxonomy resolver
"""

from __future__ import annotations

import pytest

from app.normalizers.elastic import ElasticNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    """Build an Elastic-shaped ParsedRule with sensible defaults."""
    defaults = dict(
        source="elastic",
        file_path="rules/windows/credential_access_credential_dumping.toml",
        raw_content="placeholder toml",
        title="Credential Dumping via LSASS Memory Access",
        detection_logic_raw={
            "type": "eql",
            "query": (
                'process where event.type == "start" and '
                'process.name == "lsass.exe"'
            ),
            "language": None,
        },
        description="Detects suspicious access to LSASS memory",
        author=["Elastic Security"],
        status="production",
        severity="high",
        log_source={"product": "windows"},
        tags=["Tactic: Credential Access", "Use Case: Threat Detection"],
        mitre_attack={
            "tactics": ["TA0006"],
            "techniques": ["T1003.001"],
        },
        false_positives=[],
        extra={
            "rule_id": "f3c7c540-2a85-11ef-b88e-eb7e6d2b8e7c",
            "type": "eql",
            "language": None,
            "index": ["winlogbeat-*", "logs-endpoint.events.process-*"],
            "integration": ["endpoint"],
            "references": ["https://attack.mitre.org/techniques/T1003/001/"],
            "creation_date": "2024/01/15",
            "updated_date": "2024/06/20",
            "promotion": False,
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return ElasticNormalizer("https://github.com/elastic/detection-rules")


# ── Identity / metadata ──────────────────────────────────────────────


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "elastic"
    assert n.title == "Credential Dumping via LSASS Memory Access"
    assert n.rule_id == "f3c7c540-2a85-11ef-b88e-eb7e6d2b8e7c"


def test_normalize_joins_list_author(normalizer):
    """Elastic stores author as a list — normalizer joins to a string."""
    n = normalizer.normalize(_parsed(author=["Author One", "Author Two"]))
    assert n.author == "Author One, Author Two"


def test_normalize_handles_string_author(normalizer):
    n = normalizer.normalize(_parsed(author="Single Author"))
    assert n.author == "Single Author"


# ── Status / severity ────────────────────────────────────────────────


def test_normalize_production_status_maps_to_stable(normalizer):
    """Elastic's `production` maturity is the canonical `stable`."""
    assert normalizer.normalize(_parsed(status="production")).status == "stable"


def test_normalize_development_status_maps_to_experimental(normalizer):
    assert normalizer.normalize(_parsed(status="development")).status == "experimental"


def test_normalize_severity_critical(normalizer):
    assert normalizer.normalize(_parsed(severity="critical")).severity == "critical"


# ── Language detection ──────────────────────────────────────────────


def test_normalize_detects_eql_language(normalizer):
    n = normalizer.normalize(_parsed())
    # The base test rule has type=eql.
    assert n.language == "eql"


def test_normalize_detects_kuery_as_kql(normalizer):
    n = normalizer.normalize(_parsed(
        detection_logic_raw={"type": "query", "query": "process.name : powershell.exe", "language": "kuery"},
        extra={"type": "query", "language": "kuery", "index": [], "integration": [], "promotion": False},
    ))
    assert n.language == "kql"


def test_normalize_detects_lucene(normalizer):
    n = normalizer.normalize(_parsed(
        detection_logic_raw={"type": "query", "query": "process.name:powershell.exe", "language": "lucene"},
        extra={"type": "query", "language": "lucene", "index": [], "integration": [], "promotion": False},
    ))
    assert n.language == "lucene"


# ── MITRE pass-through ──────────────────────────────────────────────


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.mitre_tactics == ["TA0006"]
    assert n.mitre_techniques == ["T1003.001"]


# ── Tags ─────────────────────────────────────────────────────────────


def test_normalize_lowercases_tags_and_underscores_spaces(normalizer):
    """`Tactic: Credential Access` → `tactic:_credential_access`. The
    canonical form is what the search service filters on."""
    n = normalizer.normalize(_parsed())
    assert "tactic:_credential_access" in n.tags
    assert "use_case:_threat_detection" in n.tags


def test_normalize_injects_building_block_tag_when_field_set(normalizer):
    """A rule whose TOML carries `rule.building_block_type` gets a
    `building_block` tag (plus a `building_block_type:<value>` tag) so
    users can filter the catalog. Per
    https://github.com/elastic/detection-rules/tree/main/rules_building_block —
    these don't fire alerts directly, only feed other rules."""
    overrides = {
        "extra": {
            "rule_id": "x",
            "type": "eql",
            "language": None,
            "index": [],
            "integration": [],
            "promotion": False,
            "building_block_type": "default",
        },
    }
    n = normalizer.normalize(_parsed(**overrides))
    assert "building_block" in n.tags
    assert "building_block_type:default" in n.tags


def test_normalize_injects_building_block_tag_from_path(normalizer):
    """Rules under `rules_building_block/` are building blocks by
    convention even when the TOML doesn't carry the field. Path-based
    detection is the safety net."""
    n = normalizer.normalize(_parsed(
        file_path="rules_building_block/credential_access/lsass_signal.toml",
    ))
    assert "building_block" in n.tags


def test_normalize_omits_building_block_tag_for_regular_rules(normalizer):
    """Regular rules do NOT get the building_block tag (default fixture
    has no building_block_type, and lives under `rules/`, not
    `rules_building_block/`)."""
    n = normalizer.normalize(_parsed())
    assert "building_block" not in n.tags
    assert not any(t.startswith("building_block_type:") for t in n.tags)


# ── Canonical taxonomy ──────────────────────────────────────────────


def test_normalize_resolves_canonical_taxonomy_for_endpoint_integration(normalizer):
    """An endpoint-integration rule with windows index pattern should
    resolve to canonical windows platform + a non-unknown event type."""
    n = normalizer.normalize(_parsed())
    assert "windows" in n.platforms
    assert n.event_types != ["unknown"]
    assert n.taxonomy_matched is True


def test_normalize_data_sources_picked_from_index_pattern(normalizer):
    """Elastic Defend index pattern resolves to canonical
    `elastic_defend` data source via the index_patterns mapping."""
    n = normalizer.normalize(_parsed())
    assert "elastic_defend" in n.data_sources


# ── Dates ────────────────────────────────────────────────────────────


def test_normalize_uses_metadata_dates(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2024
    assert n.rule_modified_date is not None
    assert n.rule_modified_date.month == 6


def test_normalize_handles_missing_dates(normalizer):
    n = normalizer.normalize(_parsed(extra={
        "rule_id": "x", "type": "eql", "index": [], "integration": [], "promotion": False,
    }))
    assert n.rule_created_date is None
    assert n.rule_modified_date is None
