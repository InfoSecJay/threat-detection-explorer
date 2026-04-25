"""Per-vendor normalizer tests for SplunkNormalizer.

Splunk-specific things to pin:
  - detection_logic_raw is ``{search, how_to_implement}``
  - language is always "spl"
  - tags get prefixes stripped except story:* which is preserved
    (the threat-pulse extractor reads it)
  - data_source field is a list of canonical Splunk data source names
  - source_rule_url branch is "develop" (not master)
"""

from __future__ import annotations

import pytest

from app.normalizers.splunk import SplunkNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="splunk",
        file_path="detections/endpoint/windows_powershell_encoded_command.yml",
        raw_content="placeholder yaml",
        title="Windows PowerShell Encoded Command",
        detection_logic_raw={
            "search": (
                "| tstats count from datamodel=Endpoint.Processes "
                "where Processes.process=*EncodedCommand* "
                "by Processes.process Processes.process_name"
            ),
            "how_to_implement": "Requires Sysmon or Endpoint datamodel.",
        },
        description="Detects encoded PowerShell command-line execution.",
        author="Splunk Threat Research Team",
        status="production",
        severity="high",
        log_source={"product": "endpoint"},
        tags=["story:hellcat_ransomware", "asset:endpoint", "domain:identity"],
        mitre_attack={"tactics": ["TA0002"], "techniques": ["T1059.001"]},
        false_positives=["Legitimate admin scripts"],
        extra={
            "id": "abc12345-def6-7890-1234-567890abcdef",
            "type": "TTP",
            "data_source": ["Sysmon EventID 1"],
            "security_domain": "endpoint",
            "references": ["https://splunk.com/example"],
            "date": "2024-03-15",
            "cve": [],
            "rba": {},
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return SplunkNormalizer("https://github.com/splunk/security_content")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "splunk"
    assert n.title == "Windows PowerShell Encoded Command"
    assert n.author == "Splunk Threat Research Team"
    assert n.rule_id == "abc12345-def6-7890-1234-567890abcdef"


def test_normalize_language_is_always_spl(normalizer):
    assert normalizer.normalize(_parsed()).language == "spl"


def test_normalize_production_status_maps_to_stable(normalizer):
    assert normalizer.normalize(_parsed(status="production")).status == "stable"


def test_normalize_severity_high(normalizer):
    assert normalizer.normalize(_parsed(severity="high")).severity == "high"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0002" in n.mitre_tactics
    assert "T1059.001" in n.mitre_techniques


def test_normalize_preserves_story_tag_prefix(normalizer):
    """The Splunk normalizer keeps `story:` prefix (threat-pulse
    extractor depends on it). Drops `asset:` and `domain:` (duplicates
    of canonical taxonomy columns)."""
    n = normalizer.normalize(_parsed())
    assert "story:hellcat_ransomware" in n.tags
    assert not any(t.startswith("asset:") for t in n.tags)
    assert not any(t.startswith("domain:") for t in n.tags)


def test_normalize_resolves_canonical_taxonomy(normalizer):
    """An endpoint rule with Sysmon EventID 1 data source should
    resolve to a non-unknown canonical taxonomy."""
    n = normalizer.normalize(_parsed())
    assert n.taxonomy_platforms != ["unknown"]
    assert n.taxonomy_matched is True


def test_normalize_uses_embedded_date_for_created(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2024
    assert n.rule_created_date.month == 3


def test_normalize_modified_date_falls_through_without_git(normalizer):
    """Splunk rules don't carry a modified date in YAML — without a
    git repo path we get None. Production fills it from git log."""
    n = normalizer.normalize(_parsed())
    assert n.rule_modified_date is None


def test_normalize_extracts_search_into_detection_logic(normalizer):
    n = normalizer.normalize(_parsed())
    assert "tstats" in n.detection_logic
    assert "EncodedCommand" in n.detection_logic


def test_normalize_source_rule_url_uses_develop_branch(normalizer):
    """Splunk's default branch is `develop`, not `master`."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "/develop/" in n.source_rule_url
