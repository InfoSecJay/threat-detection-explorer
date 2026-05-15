"""Per-vendor normalizer tests for LOLRMMNormalizer.

LOLRMM is Sigma-format rules describing remote-management-tool abuse:
  - Each "rule" is a named RMM tool (TeamViewer, AnyDesk, NetSupport, etc.)
  - language is "sigma" (the format) but the canonical platform is
    almost always Windows
  - Defaults to platform=windows + event_category=process when the
    taxonomy doesn't pick something more specific
"""

from __future__ import annotations

import pytest

from app.normalizers.lolrmm import LOLRMMNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="lolrmm",
        file_path="yml/RMM_Tool/AnyDesk.yml",
        raw_content="placeholder yaml",
        title="AnyDesk Remote Access Tool Execution",
        detection_logic_raw={
            "selection": {
                "Image|endswith": "\\anydesk.exe",
            },
            "condition": "selection",
        },
        description="Detects AnyDesk RMM tool execution.",
        author="LOLRMM Project",
        status="stable",
        severity="medium",
        log_source={"product": "windows", "category": "process_creation"},
        tags=["lolrmm", "attack.command_and_control"],
        mitre_attack={"tactics": ["TA0011"], "techniques": ["T1219"]},
        false_positives=["Authorized remote IT support"],
        extra={
            "id": "lolrmm-anydesk-001",
            "references": ["https://anydesk.com"],
            "date": "2023/06/01",
            "modified": "2024/02/14",
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return LOLRMMNormalizer("https://github.com/magicsword-io/LOLRMM")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "lolrmm"
    assert n.title == "AnyDesk Remote Access Tool Execution"
    assert n.rule_id == "lolrmm-anydesk-001"


def test_normalize_language_is_sigma_format(normalizer):
    """LOLRMM uses Sigma rule format under the hood."""
    assert normalizer.normalize(_parsed()).language == "sigma"


def test_normalize_severity_medium(normalizer):
    assert normalizer.normalize(_parsed(severity="medium")).severity == "medium"


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert "TA0011" in n.mitre_tactics
    assert "T1219" in n.mitre_techniques


def test_normalize_platform_defaults_to_windows(normalizer):
    """Almost every RMM rule is Windows-context; the legacy `platform`
    column is forced to `windows` if the resolver doesn't pick anything."""
    n = normalizer.normalize(_parsed())
    assert "windows" in n.platforms


def test_normalize_event_category_defaults_to_process(normalizer):
    """LOLRMM rules are RMM tool detection -- canonical event type
    is `process_creation`."""
    n = normalizer.normalize(_parsed())
    assert "process_creation" in n.event_types


def test_normalize_lolrmm_tag_preserved(normalizer):
    """The bare `lolrmm` tag is kept verbatim."""
    n = normalizer.normalize(_parsed())
    assert "lolrmm" in n.tags


def test_normalize_uses_embedded_dates(normalizer):
    """LOLRMM uses Sigma's `date` + `modified` fields when present."""
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2023
    assert n.rule_modified_date is not None
    assert n.rule_modified_date.year == 2024


def test_normalize_extracts_process_from_detection(normalizer):
    """Sigma extractor catches the .exe in the Image|endswith pattern."""
    n = normalizer.normalize(_parsed())
    assert any("anydesk.exe" in p.lower() for p in n.extracted_process_names)


def test_normalize_handles_missing_dates(normalizer):
    n = normalizer.normalize(_parsed(extra={"id": "x"}))
    assert n.rule_created_date is None
    assert n.rule_modified_date is None
