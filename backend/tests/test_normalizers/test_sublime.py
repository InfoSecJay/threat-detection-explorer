"""Per-vendor normalizer tests for SublimeNormalizer.

Sublime-specific things to pin:
  - Always email security — platform falls back to "email" if the
    taxonomy resolver doesn't pick a more specific value
  - language is always "mql"
  - tags include `Malfam: <Name>` form which the threat-pulse
    extractor reads
"""

from __future__ import annotations

import pytest

from app.normalizers.sublime import SublimeNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="sublime",
        file_path="detection-rules/attachment/qakbot_phishing.yml",
        raw_content="placeholder yaml",
        title="Phishing attachment from QakBot delivery campaign",
        detection_logic_raw=(
            'any(attachments, .file_extension in~ ["zip", "iso", "img"])\n'
            'and length(attachments) >= 1\n'
            'and any(headers.from, .domain in $suspicious_domains)\n'
        ),
        description="Detects QakBot delivery via container attachments.",
        author="Sublime Security",
        status="stable",
        severity="high",
        log_source={"product": "email", "category": "email_security"},
        tags=["Attack surface reduction", "Malfam: QakBot"],
        mitre_attack={"tactics": ["TA0001"], "techniques": ["T1566.001"]},
        false_positives=[],
        extra={
            "id": "12345-sublime-rule-id",
            "references": ["https://abuse.ch/url/qakbot"],
            "tactics_and_techniques": ["Social engineering"],
            "type": "rule",
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return SublimeNormalizer("https://github.com/sublime-security/sublime-rules")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "sublime"
    assert n.title == "Phishing attachment from QakBot delivery campaign"


def test_normalize_language_is_always_mql(normalizer):
    assert normalizer.normalize(_parsed()).language == "mql"


def test_normalize_platform_defaults_to_email(normalizer):
    """Sublime is always email-context — platform is `email` if the
    taxonomy resolver doesn't override."""
    n = normalizer.normalize(_parsed())
    assert n.platform == "email"


def test_normalize_event_category_defaults_to_email(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.event_category == "email"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0001" in n.mitre_tactics
    assert "T1566.001" in n.mitre_techniques


def test_normalize_preserves_malfam_tag(normalizer):
    """`Malfam: QakBot` is verbatim — threat-pulse extracts on this prefix."""
    n = normalizer.normalize(_parsed())
    assert "Malfam: QakBot" in n.tags


def test_normalize_canonical_taxonomy_resolves_to_email(normalizer):
    """Even though the canonical resolver may match `unknown`, the
    legacy `platform` column is forced to `email`. Asserts that
    behavior so future taxonomy changes don't accidentally drop it."""
    n = normalizer.normalize(_parsed())
    assert n.platform == "email"


def test_normalize_dates_are_none_without_git_fallback(normalizer):
    """Sublime YAML has no date fields; without a repo_path we get
    None for both."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is None
    assert n.rule_modified_date is None


def test_normalize_preserves_query_in_detection_logic(normalizer):
    n = normalizer.normalize(_parsed())
    assert "attachments" in n.detection_logic
    assert "suspicious_domains" in n.detection_logic
