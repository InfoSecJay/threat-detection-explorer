"""Per-vendor normalizer tests for GoogleSecOpsNormalizer.

Google SecOps (Chronicle) specifics to pin:
  - language is always `yaral`
  - explicit `platform` / `data_source` meta -> canonical taxonomy
  - rule status forced to `stable` (Chronicle uses `type = "Alert"`
    which isn't a status; community rules in main are stable)
  - MITRE techniques from the mitre_attack_url URL form
  - Field extraction NOT yet implemented (deferred follow-up); all
    extracted_* lists land empty
"""

from __future__ import annotations

import pytest

from app.normalizers.google_secops import GoogleSecOpsNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="google_secops",
        file_path="rules/community/aws/cloudtrail/aws_console_login_without_mfa.yaral",
        raw_content="rule placeholder { meta: ... events: ... condition: ... }",
        title="AWS Console Login Without MFA",
        detection_logic_raw=(
            "meta:\n"
            '  author = "Google Cloud Security"\n'
            'events:\n'
            '  $login.metadata.event_type = "USER_LOGIN"\n'
            'condition:\n'
            '  $login'
        ),
        description="Detect when a user logs into AWS console without MFA.",
        author="Google Cloud Security",
        status="stable",
        severity="Low",
        log_source={"platform": "AWS", "data_source": "AWS CloudTrail"},
        tags=["aws", "aws_cloudtrail", "alert"],
        mitre_attack={
            "tactics": ["TA0001"],
            "techniques": ["T1078.004", "T1078"],
        },
        false_positives=[],
        extra={
            "rule_id": "mr_b03d1e57-7ed0-49e7-b125-6c18b364ae8c",
            "rule_name": "AWS Console Login Without MFA",
            "type": "Alert",
            "platform": "AWS",
            "data_source": "AWS CloudTrail",
            "mitre_attack_url": "https://attack.mitre.org/techniques/T1078/004/",
            "priority": "Low",
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return GoogleSecOpsNormalizer(
        "https://github.com/chronicle/detection-rules"
    )


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "google_secops"
    assert n.title == "AWS Console Login Without MFA"
    assert n.rule_id == "mr_b03d1e57-7ed0-49e7-b125-6c18b364ae8c"


def test_normalize_language_is_always_yaral(normalizer):
    """Chronicle rules are YARA-L 2.0; canonical token is `yaral`."""
    assert normalizer.normalize(_parsed()).language == "yaral"


def test_normalize_explicit_platform_meta_maps_to_canonical(normalizer):
    """`platform = "AWS"` -> canonical platform `aws`."""
    n = normalizer.normalize(_parsed())
    assert "aws" in n.products
    assert "aws" in n.products


def test_normalize_explicit_data_source_meta_maps_to_canonical(normalizer):
    """`data_source = "AWS CloudTrail"` -> canonical
    `aws_cloudtrail` with the api_call event_type from the resolver."""
    n = normalizer.normalize(_parsed())
    assert "aws_cloudtrail" in n.data_sources
    assert "aws_cloudtrail" in n.data_sources
    assert "api_call" in n.event_types


def test_normalize_severity_low_lowercased(normalizer):
    """Chronicle uses Title Case severity (Low/Medium/High); normalize
    to canonical lowercase."""
    n = normalizer.normalize(_parsed(severity="High"))
    assert n.severity == "high"


def test_normalize_status_forced_stable(normalizer):
    """Chronicle's `type` meta (`Alert` / `Hunt`) is NOT a status -- the
    parser sets `status = "stable"` directly because community rules
    in main are stable."""
    n = normalizer.normalize(_parsed())
    assert n.status == "stable"


def test_normalize_passes_mitre_through(normalizer):
    """MITRE techniques + tactics extracted by the parser flow through."""
    n = normalizer.normalize(_parsed())
    assert "T1078.004" in n.mitre_techniques
    assert "TA0001" in n.mitre_tactics


def test_normalize_microsoft_platform_resolves(normalizer):
    """`platform = "Microsoft"` -> canonical platform `microsoft_365`."""
    n = normalizer.normalize(_parsed(
        file_path="rules/community/microsoft/m365/foo.yaral",
        log_source={"platform": "Microsoft", "data_source": "Office 365"},
        extra={
            "rule_id": "x", "rule_name": "x", "type": "Alert",
            "platform": "Microsoft", "data_source": "Office 365",
        },
    ))
    assert "microsoft_365" in n.products


def test_normalize_folder_fallback_when_meta_missing(normalizer):
    """When the explicit `platform` meta is missing, the resolver
    falls back to the `rules/community/<vendor>/` folder. A rule
    placed in `community/github/` with no platform meta resolves to
    [github]."""
    n = normalizer.normalize(_parsed(
        file_path="rules/community/github/some_audit_rule.yaral",
        log_source={"platform": None, "data_source": None},
        extra={
            "rule_id": "x", "rule_name": "x", "type": "Alert",
            "platform": None, "data_source": None,
        },
    ))
    assert "github" in n.products
    assert "github_audit" in n.data_sources


def test_normalize_runs_yaral_extraction(normalizer):
    """The events: block is extracted (issue #6 tail): UDM paths land in
    fields_used and typed observables carry the compared values."""
    n = normalizer.normalize(_parsed())
    assert "metadata.event_type" in n.extracted_fields_used
    assert isinstance(n.extracted_observables, list)


def test_normalize_source_rule_url_deep_links_to_repo(normalizer):
    """The source URL should land on the Chronicle repo's main branch
    at the exact rule path."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "chronicle/detection-rules" in n.source_rule_url
    assert "rules/community/aws/cloudtrail/aws_console_login_without_mfa.yaral" in n.source_rule_url


def test_normalize_default_author_is_google_cloud_security(normalizer):
    """When the author meta is missing, fall back to the publisher."""
    n = normalizer.normalize(_parsed(author=None))
    assert n.author == "Google Cloud Security"
