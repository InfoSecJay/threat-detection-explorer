"""Per-vendor normalizer tests for OktaNormalizer.

Okta customer-detections specifics to pin:
  - language picks primary by priority (OIE > spl > datadog)
  - platform is always `okta`, data_source `okta_system_log`
  - severity defaults to `medium` (upstream YAML doesn't carry it)
  - status forced to `stable`
  - MITRE technique IDs extracted from the threat.Technique block
  - source_rule_url uses the `master` branch (Okta's default)
"""

from __future__ import annotations

import pytest

from app.normalizers.okta import OktaNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="okta",
        file_path="detections/access_to_admin_console_denied.yml",
        raw_content="placeholder yaml",
        title="Access to Admin Console Denied",
        detection_logic_raw=(
            'eventType eq "user.session.access_admin_app" AND outcome.result eq "FAILURE"'
        ),
        description="Detects when an attempt was made to access the Okta Admin Console but failed.",
        author="Okta",
        status="stable",
        severity="medium",
        log_source={"product": "okta", "category": "system_log"},
        tags=["query:oie"],
        mitre_attack={
            "tactics": ["TA0001"],
            "techniques": ["T1078"],
        },
        false_positives=["Legitimate administrative users causing a failure"],
        extra={
            "id": "e6e88bfdbc27a65cddf1225c9ff0fb12",
            "references": ["https://sec.okta.com/leastprivilege"],
            "created_date": "2022-10-22",
            "modified_date": "2022-10-22",
            "primary_language": "oie",
            "all_queries": {"oie": "eventType eq ..."},
            "prevention": ["Implement Zero Standing Privileges"],
            "explanation": None,
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return OktaNormalizer(
        "https://github.com/okta/customer-detections"
    )


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "okta"
    assert n.title == "Access to Admin Console Denied"
    assert n.rule_id == "e6e88bfdbc27a65cddf1225c9ff0fb12"


def test_normalize_language_is_primary_oie_when_present(normalizer):
    """Primary OIE rules tag as `oie` (lowercase canonical token)."""
    assert normalizer.normalize(_parsed()).language == "oie"


def test_normalize_language_can_be_spl_for_splunk_rules(normalizer):
    """Rules whose primary query is SPL tag as `spl`."""
    n = normalizer.normalize(_parsed(extra={
        "id": "x", "references": [], "created_date": None, "modified_date": None,
        "primary_language": "spl",
        "all_queries": {"spl": "index=main eventType=..."},
        "prevention": [], "explanation": None,
    }))
    assert n.language == "spl"


def test_normalize_platform_is_always_okta(normalizer):
    n = normalizer.normalize(_parsed())
    assert "okta" in n.products
    assert "okta" in n.products


def test_normalize_data_source_is_always_okta_system_log(normalizer):
    n = normalizer.normalize(_parsed())
    assert "okta_system_log" in n.data_sources
    assert "okta_system_log" in n.data_sources


def test_normalize_event_type_is_authentication(normalizer):
    """Okta detections cluster heavily on authentication events;
    canonical event_type defaults to `authentication` for all rules."""
    n = normalizer.normalize(_parsed())
    assert "authentication" in n.event_types
    assert "authentication" in n.event_types


def test_normalize_severity_default_medium(normalizer):
    """Upstream YAML lacks severity; parser sets `medium` and
    normalizer passes it through canonical normalization."""
    n = normalizer.normalize(_parsed())
    assert n.severity == "medium"


def test_normalize_status_stable(normalizer):
    """Community-published rules in main are stable by convention."""
    n = normalizer.normalize(_parsed())
    assert n.status == "stable"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "T1078" in n.mitre_techniques
    assert "TA0001" in n.mitre_tactics


def test_normalize_embedded_dates_resolved(normalizer):
    """`created_date` and `modified_date` from the YAML land on the
    normalized fields after going through `parse_date`."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2022
    assert n.rule_modified_date is not None


def test_normalize_source_rule_url_uses_master_branch(normalizer):
    """Okta's default branch is `master` (not `main`)."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "okta/customer-detections" in n.source_rule_url
    assert "/blob/master/detections/" in n.source_rule_url


def test_normalize_default_author_is_okta(normalizer):
    """When the author field is missing, fall back to Okta."""
    n = normalizer.normalize(_parsed(author=None))
    assert n.author == "Okta"
