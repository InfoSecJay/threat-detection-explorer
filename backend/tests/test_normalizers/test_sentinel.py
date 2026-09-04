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
    assert n.platforms  # never empty


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0009" in n.mitre_tactics
    assert "T1114.003" in n.mitre_techniques


def test_normalize_preserves_tags_verbatim(normalizer):
    """Sentinel tags include bare threat-actor codenames (NOBELIUM,
    Solorigate). They pass through unmodified."""
    n = normalizer.normalize(_parsed())
    assert "NOBELIUM" in n.tags


def test_threat_tags_become_story_labels(normalizer, monkeypatch):
    """Tags naming a threat actor land verbatim in use_cases (issue
    #20) — the dedicated tier resolves story labels to actors at query
    time. Framework tags stay out; `tags` passthrough is untouched."""
    from app.services.actor_context import actor_context_service

    monkeypatch.setattr(
        actor_context_service, "_alias_to_gids", {"nobelium": ["G0016"]}
    )
    n = normalizer.normalize(
        _parsed(tags=["NOBELIUM", "DEV-0537", "NIST 800-53 r5", "SigninLogs"])
    )
    # NOBELIUM via the alias registry, DEV-0537 via the tracking-code
    # pattern; compliance/table tags don't classify.
    assert n.use_cases == ["NOBELIUM", "DEV-0537"]
    assert n.tags == ["NOBELIUM", "DEV-0537", "NIST 800-53 r5", "SigninLogs"]


def test_normalize_resolves_canonical_taxonomy_for_office_activity(normalizer):
    """An OfficeActivity-querying rule should resolve to the
    `microsoft_365` canonical platform via the Sentinel KQL-table
    extractor + taxonomy mapping."""
    n = normalizer.normalize(_parsed())
    assert n.platforms != ["unknown"]
    assert "microsoft_365" in n.products
    assert "audit_event" in n.event_types
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


def test_security_alert_maps_to_microsoft_platforms_not_cross_platform(normalizer):
    """SecurityAlert is Sentinel's central alert table -- sources are
    overwhelmingly Microsoft Defender services (XDR, MDC, MDE, MDI,
    MCAS). Audit Phase 2 surfaced this as the dominant cross_platform
    contributor; the correct mapping is the actual Microsoft platforms."""
    n = normalizer.normalize(_parsed(
        detection_logic_raw="SecurityAlert | where ProviderName == 'MDATP'",
        extra={"id": "x", "kql_tables": ["SecurityAlert"]},
    ))
    assert "cross_platform" not in n.platforms
    assert "microsoft_365" in n.products
    assert "azure" in n.products
    assert "windows" in n.platforms


def test_behavior_analytics_maps_to_azure_not_cross_platform(normalizer):
    """Sentinel UEBA is an Azure-resident feature."""
    n = normalizer.normalize(_parsed(
        detection_logic_raw="BehaviorAnalytics | where ActivityType == 'LogOn'",
        extra={"id": "x", "kql_tables": ["BehaviorAnalytics"]},
    ))
    assert "cross_platform" not in n.platforms
    assert "azure" in n.products


def test_ado_audit_logs_maps_to_azure_not_cross_platform(normalizer):
    """Azure DevOps audit logs are an Azure service."""
    n = normalizer.normalize(_parsed(
        detection_logic_raw="ADOAuditLogs | where ActivityType == 'ProjectCreated'",
        extra={"id": "x", "kql_tables": ["ADOAuditLogs"]},
    ))
    assert "cross_platform" not in n.platforms
    assert "azure" in n.products


def test_threat_intel_indicator_maps_to_azure(normalizer):
    """Sentinel TI ingest table -- Azure-resident."""
    n = normalizer.normalize(_parsed(
        detection_logic_raw="ThreatIntelligenceIndicator | where ConfidenceScore > 75",
        extra={"id": "x", "kql_tables": ["ThreatIntelligenceIndicator"]},
    ))
    assert "cross_platform" not in n.platforms
    assert "azure" in n.products


def test_unknown_cl_table_does_not_inject_cross_platform(normalizer):
    """An unrecognized custom-log `*_CL` table shouldn't poison the
    rule's platform with `cross_platform`. The `*_cl` catch-all
    contributes a `siem_alert` data_source but no platform; the rule
    falls back to whatever connectors / solution_folders resolve. If
    nothing resolves, it lands on [unknown], not cross_platform."""
    n = normalizer.normalize(_parsed(
        file_path="Solutions/Unknown Vendor/Analytic Rules/whatever.yaml",
        detection_logic_raw="SomeUnknownVendorTable_CL | where Severity == 'High'",
        extra={"id": "x", "kql_tables": ["SomeUnknownVendorTable_CL"]},
    ))
    assert "cross_platform" not in n.platforms
    assert "siem_alert" in n.data_sources


def test_unknown_cl_data_type_does_not_inject_cross_platform(normalizer):
    """The resolver's dataType `_cl` fallback (in vendors/sentinel.py)
    previously added `cross_platform` for any *_CL dataType -- same
    poisoning class as the kql_tables `*_cl` catch-all. Should now
    contribute siem_alert only."""
    n = normalizer.normalize(_parsed(
        detection_logic_raw="MyVendorTable_CL | where Field1 == 'x'",
        extra={
            "id": "x",
            "kql_tables": [],  # force resolver to fall through to dataTypes
            "requiredDataConnectors": [
                {"connectorId": "MyVendorConnector", "dataTypes": ["MyVendor_CL"]}
            ],
        },
    ))
    assert "cross_platform" not in n.platforms
    assert "siem_alert" in n.data_sources
