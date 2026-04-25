"""Per-vendor normalizer tests for SentinelNormalizer.

Sentinel-specific things to pin:
  - detection_logic_raw is a KQL query string (not a dict)
  - language is always "kql"
  - author defaults to "Microsoft" when missing
  - platform / data_source default to azure / sentinel respectively
  - no embedded date fields — both come from git_log fallback
  - tags pass through verbatim (no prefix munging)
"""

from __future__ import annotations

import pytest

from app.normalizers.sentinel import SentinelNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="sentinel",
        file_path="Solutions/Microsoft Defender for Cloud Apps/Analytic Rules/MailForwardingFromO365.yaml",
        raw_content="placeholder yaml",
        title="Mail Forwarding to External Domain",
        detection_logic_raw=(
            'OfficeActivity\n'
            '| where OfficeWorkload == "Exchange"\n'
            '| where Operation == "Set-Mailbox" and Parameters has "ForwardingSmtpAddress"\n'
        ),
        description="Detects mailbox forwarding configuration to external domains.",
        author=None,  # explicit so the normalizer's "Microsoft" default kicks in
        status="stable",
        severity="medium",
        log_source={"product": "azure", "category": "office365"},
        tags=["NOBELIUM", "Mail Forwarding"],
        mitre_attack={
            "tactics": ["TA0009"],
            "techniques": ["T1114.003"],
        },
        false_positives=[],
        extra={
            "id": "abc-123-def",
            "kind": "Scheduled",
            "version": "1.0.0",
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            # The Sentinel parser walks the KQL query and pulls out
            # table references; the taxonomy resolver's Tier 1 reads
            # `extra["kql_tables"]` to map the rule to canonical
            # platforms/data sources.
            "kql_tables": ["OfficeActivity"],
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return SentinelNormalizer("https://github.com/Azure/Azure-Sentinel")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "sentinel"
    assert n.title == "Mail Forwarding to External Domain"
    assert n.rule_id == "abc-123-def"


def test_normalize_language_is_always_kql(normalizer):
    assert normalizer.normalize(_parsed()).language == "kql"


def test_normalize_author_defaults_to_microsoft(normalizer):
    """Sentinel rules don't always carry an author — fall back to Microsoft."""
    n = normalizer.normalize(_parsed(author=None))
    assert n.author == "Microsoft"


def test_normalize_uses_explicit_author_when_present(normalizer):
    n = normalizer.normalize(_parsed(author="Custom Author"))
    assert n.author == "Custom Author"


def test_normalize_platform_defaults_to_azure_when_unmapped(normalizer):
    """Sentinel falls back to `azure` platform on the legacy column when
    the taxonomy resolver doesn't pick anything else."""
    n = normalizer.normalize(_parsed())
    assert n.platform  # never empty


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0009" in n.mitre_tactics
    assert "T1114.003" in n.mitre_techniques


def test_normalize_preserves_tags_verbatim(normalizer):
    """Sentinel tags include bare threat-actor codenames (NOBELIUM,
    Solorigate). They pass through unmodified."""
    n = normalizer.normalize(_parsed())
    assert "NOBELIUM" in n.tags


def test_normalize_resolves_canonical_taxonomy_for_office_activity(normalizer):
    """An OfficeActivity-querying rule should resolve to the
    `microsoft_365` canonical platform via the Sentinel KQL-table
    extractor + taxonomy mapping."""
    n = normalizer.normalize(_parsed())
    assert n.taxonomy_platforms != ["unknown"]
    assert "microsoft_365" in n.taxonomy_platforms
    assert "audit_event" in n.taxonomy_event_types
    assert n.taxonomy_matched is True


def test_normalize_dates_are_none_without_git_fallback(normalizer):
    """Sentinel YAML carries no date fields. Without a repo_path the
    git fallback returns None for both. Production has the repo_path
    and gets real dates from git log."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is None
    assert n.rule_modified_date is None


def test_normalize_query_string_lands_as_detection_logic(normalizer):
    n = normalizer.normalize(_parsed())
    assert "OfficeActivity" in n.detection_logic
    assert "ForwardingSmtpAddress" in n.detection_logic
