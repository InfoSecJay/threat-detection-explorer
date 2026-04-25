"""Per-vendor normalizer tests for ElasticProtectionsNormalizer.

Elastic Protections specifics:
  - detection_logic_raw is an EQL string
  - language is always "eql"
  - all rules are behavior/endpoint-class — data_sources always
    includes the `endpoint` family
  - event_category falls back to `process` when the platform is
    a recognized OS but no event_category was extracted
"""

from __future__ import annotations

import pytest

from app.normalizers.elastic_protections import ElasticProtectionsNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="elastic_protections",
        file_path="behavior/rules/windows/credential_access_lsass_handle.toml",
        raw_content="placeholder toml",
        title="Suspicious LSASS Handle Acquisition",
        detection_logic_raw=(
            'process where event.action == "process_handle" '
            'and target.process.name == "lsass.exe"'
        ),
        description="Detects suspicious handle acquisition on LSASS.",
        author="Elastic",
        status="stable",
        severity="high",
        log_source={"product": "windows", "category": ""},
        tags=["behavior_rule", "endpoint_protection", "windows"],
        mitre_attack={"tactics": ["TA0006"], "techniques": ["T1003.001"]},
        false_positives=[],
        extra={
            "id": "abcd-1234",
            "version": "1.0.0",
            "license": "Elastic License v2",
            "min_endpoint_version": "8.10.0",
            "actions": [],
            # The taxonomy resolver pulls os_list from extra to map to
            # canonical platforms.
            "os_list": ["windows"],
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return ElasticProtectionsNormalizer(
        "https://github.com/elastic/protections-artifacts"
    )


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "elastic_protections"
    assert n.title == "Suspicious LSASS Handle Acquisition"
    assert n.author == "Elastic"


def test_normalize_language_is_always_eql(normalizer):
    assert normalizer.normalize(_parsed()).language == "eql"


def test_normalize_severity_high(normalizer):
    assert normalizer.normalize(_parsed(severity="high")).severity == "high"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0006" in n.mitre_tactics
    assert "T1003.001" in n.mitre_techniques


def test_normalize_event_category_defaults_to_process_for_os_rules(normalizer):
    """Behavior rules on a recognised OS get a `process` event_category
    even if the resolver doesn't pick one."""
    n = normalizer.normalize(_parsed())
    assert n.event_category == "process"


def test_normalize_data_sources_always_include_endpoint(normalizer):
    """Every Elastic Protections rule is endpoint-class."""
    n = normalizer.normalize(_parsed())
    assert any("endpoint" in ds.lower() for ds in n.data_sources)


def test_normalize_dates_are_none_without_git_fallback(normalizer):
    """Elastic Protections TOML has no date fields; without a
    repo_path we get None for both."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is None
    assert n.rule_modified_date is None


def test_normalize_query_lands_in_detection_logic(normalizer):
    n = normalizer.normalize(_parsed())
    assert "lsass.exe" in n.detection_logic
    assert "process_handle" in n.detection_logic
