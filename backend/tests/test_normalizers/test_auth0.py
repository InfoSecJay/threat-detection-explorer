"""Per-vendor normalizer tests for Auth0Normalizer.

Auth0 specifics to pin:
  - language is `spl` when the upstream YAML carries a `splunk:`
    implementation (true for all 33 community rules); falls back
    to `sigma` when only the Sigma `detection:` block is present
  - detection_logic shows the SPL query verbatim when language=spl
  - platform is always `auth0`, data_source `auth0_logs`
  - event_type defaults to `authentication` (corpus is auth-heavy)
  - source_rule_url uses the `main` branch
  - MITRE tactic/technique IDs extracted from `attack.t<id>` tags
    via the shared Sigma tag extractor
  - Embedded `date` / `modified` round-trip to created/modified
"""

from __future__ import annotations

import pytest

from app.normalizers.auth0 import Auth0Normalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="auth0",
        file_path="detections/attack_protection_features_turned_off.yml",
        raw_content="placeholder yaml",
        title="Attack protection features manipulation",
        detection_logic_raw={
            "selection": {
                "data.type": "sapi",
                "data.description": ["Update Brute-force settings"],
            },
            "condition": "selection",
        },
        description="Detects when attack protection features have been disabled.",
        author="Okta",
        status="experimental",
        severity="medium",
        log_source={"product": "auth0", "category": None, "service": None},
        tags=[],
        mitre_attack={
            "tactics": ["TA0005"],
            "techniques": ["T1562", "T1562.007"],
        },
        false_positives=["Legitimate updates by an administrator."],
        extra={
            "id": "0325e11e-12ce-44e7-8d1f-3a64700a000a",
            "date": "2025-07-11",
            "modified": "2025-09-01",
            "splunk_query": 'index=auth0 data.type=sapi\n| stats count by data.description',
            "tenant_logs_query": 'type: "sapi"',
            "prevention": ["Control tenant admins."],
            "comments": ["Tune for tenant name."],
            "explanation": "Collects modification events.",
            "references": [],
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return Auth0Normalizer("https://github.com/auth0/auth0-customer-detections")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "auth0"
    assert n.title == "Attack protection features manipulation"
    assert n.rule_id == "0325e11e-12ce-44e7-8d1f-3a64700a000a"


def test_normalize_language_prefers_splunk_when_present(normalizer):
    """The upstream YAML ships both a Sigma `detection:` block AND a
    `splunk:` implementation. The Splunk query is what an analyst
    would actually run, so we surface it as primary -- language `spl`
    and detection_logic = the SPL query verbatim."""
    n = normalizer.normalize(_parsed())
    assert n.language == "spl"
    assert "index=auth0" in n.detection_logic
    assert "stats count by data.description" in n.detection_logic


def test_normalize_language_falls_back_to_sigma_when_no_splunk(normalizer):
    """If a rule ever ships without a `splunk:` implementation, we
    render the Sigma `detection:` block as YAML and tag language
    `sigma`. None of the 33 current community rules hit this path
    but the fallback exists for defensive resilience."""
    n = normalizer.normalize(_parsed(extra={
        "id": "x", "date": "2025-01-01", "modified": "2025-01-01",
        "splunk_query": None,  # no SPL implementation
        "tenant_logs_query": None, "prevention": [],
        "comments": [], "explanation": None, "references": [],
    }))
    assert n.language == "sigma"
    # The Sigma block (rendered as YAML) is in detection_logic.
    assert "data.type" in n.detection_logic


def test_normalize_platform_is_always_auth0(normalizer):
    n = normalizer.normalize(_parsed())
    assert "auth0" in n.platforms


def test_normalize_data_source_is_always_auth0_logs(normalizer):
    n = normalizer.normalize(_parsed())
    assert "auth0_logs" in n.data_sources


def test_normalize_event_type_defaults_to_authentication(normalizer):
    """Auth0 corpus is auth-heavy; canonical event_type defaults
    to `authentication` via always_includes."""
    n = normalizer.normalize(_parsed())
    assert "authentication" in n.event_types


def test_normalize_severity_normalized_from_sigma_level(normalizer):
    """Auth0 uses Sigma's `level` field -- normalize to canonical."""
    n = normalizer.normalize(_parsed(severity="high"))
    assert n.severity == "high"


def test_normalize_status_experimental(normalizer):
    """`status: experimental` round-trips through canonical norm."""
    n = normalizer.normalize(_parsed())
    assert n.status == "experimental"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "T1562.007" in n.mitre_techniques
    assert "TA0005" in n.mitre_tactics


def test_normalize_embedded_dates_resolved(normalizer):
    """`date` and `modified` from the Sigma YAML land on the
    canonical date fields after going through `parse_date`."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2025
    assert n.rule_modified_date is not None


def test_normalize_source_rule_url_uses_main_branch(normalizer):
    """Auth0's default branch is `main`."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "auth0/auth0-customer-detections" in n.source_rule_url
    assert "/blob/main/detections/" in n.source_rule_url


def test_normalize_default_author_is_okta(normalizer):
    """Auth0 is Okta-owned; rules ship with `author: Okta`. Fall
    back to that brand name if the field is missing."""
    n = normalizer.normalize(_parsed(author=None))
    assert n.author == "Okta"
