"""Per-vendor normalizer tests for PantherNormalizer.

Panther specifics to pin:
  - detection_logic = the .py source verbatim; language = 'python'
  - fallback: correlation/declarative rules with no .py sibling render
    the YAML Detection block; language = 'panther_correlation' /
    'panther' respectively
  - LogTypes -> canonical platforms/data_sources/event_types via the
    Panther-specific vendor resolver
  - multi-LogType rules union across every LogType
  - MITRE tactics + techniques extracted from `Reports.MITRE ATT&CK`
    (colon-joined `TA####:T####` format, distinct from Sigma's
    `attack.t*` convention)
  - Non-MITRE Reports families (CIS, PCI, etc.) preserved as
    `report:*` prefixed tags
  - Signal-only rules (CreateAlert: false OR panther-signal tag)
    stamped `experimental` for now (see issue #26)
  - Deprecated rules stamped `deprecated` via `deprecated.txt` lookup
  - source_rule_url uses the `develop` branch
"""

from __future__ import annotations

import pytest

from app.normalizers.panther import PantherNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="panther",
        file_path="rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml",
        raw_content="AnalysisType: rule\nRuleID: AWS.CloudTrail.Stopped\n",
        title="CloudTrail Was Stopped",
        detection_logic_raw='def rule(event):\n    return event.get("eventName") == "StopLogging"\n',
        description="Detects StopLogging API calls that turn off CloudTrail.",
        author=None,
        status="stable",
        severity="High",
        log_source={"product": "aws", "category": None, "service": None},
        tags=["Defense Evasion:Impair Defenses", "report:cis", "report:stratus_red_team"],
        mitre_attack={
            "tactics": ["TA0005"],
            "techniques": ["T1562.008"],
            "groups": [],
            "software": [],
        },
        false_positives=[],
        extra={
            "id": "AWS.CloudTrail.Stopped",
            "display_name": "CloudTrail Was Stopped",
            "language": "python",
            "analysis_type": "rule",
            "log_types": ["AWS.CloudTrail"],
            "reference": ["https://example.com/mitre-t1562-008"],
            "runbook": "Investigate the actor.",
            "dedup_period_minutes": 60,
            "threshold": 1,
            "create_alert": True,
            "enabled": True,
            "is_signal_only": False,
            "reports": {
                "MITRE ATT&CK": ["TA0005:T1562.008"],
                "CIS": ["3.5"],
                "Stratus Red Team": ["aws.defense-evasion.cloudtrail-stop"],
            },
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    return PantherNormalizer("https://github.com/panther-labs/panther-analysis")


def test_normalize_preserves_metadata(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.source == "panther"
    assert n.title == "CloudTrail Was Stopped"
    assert n.rule_id == "AWS.CloudTrail.Stopped"


def test_normalize_language_is_python(normalizer):
    """Standard rules ship a .py sibling; language reflects it."""
    n = normalizer.normalize(_parsed())
    assert n.language == "python"


def test_normalize_detection_logic_is_py_verbatim(normalizer):
    """The .py source is surfaced verbatim (parser sets detection_logic_raw)."""
    n = normalizer.normalize(_parsed())
    assert 'event.get("eventName") == "StopLogging"' in n.detection_logic


def test_normalize_language_correlation(normalizer):
    """Correlation rules have no .py; parser sets language accordingly."""
    n = normalizer.normalize(_parsed(
        extra={**_parsed().extra, "language": "panther_correlation", "analysis_type": "correlation_rule", "log_types": []},
        detection_logic_raw="Group:\n  - RuleID: SomeChildRule\n",
    ))
    assert n.language == "panther_correlation"


def test_normalize_platform_from_log_type(normalizer):
    """LogTypes -> canonical platforms via the Panther resolver."""
    n = normalizer.normalize(_parsed())
    assert "aws" in n.platforms


def test_normalize_data_source_from_log_type(normalizer):
    n = normalizer.normalize(_parsed())
    assert "aws_cloudtrail" in n.data_sources


def test_normalize_event_type_from_log_type(normalizer):
    n = normalizer.normalize(_parsed())
    assert "api_call" in n.event_types


def test_normalize_multi_log_type_unions(normalizer):
    """A rule with 3 LogTypes unions all their canonical values."""
    n = normalizer.normalize(_parsed(
        extra={**_parsed().extra, "log_types": ["OneLogin.Events", "AWS.CloudTrail", "Zoom.Operation"]},
    ))
    assert {"aws", "onelogin", "zoom"}.issubset(n.platforms)
    assert {"aws_cloudtrail", "onelogin_events", "zoom_operation"}.issubset(n.data_sources)


def test_normalize_severity_normalized(normalizer):
    """Panther uses `Info | Low | Medium | High | Critical` — Info folds
    into `low` via the base normalizer."""
    n = normalizer.normalize(_parsed(severity="Critical"))
    assert n.severity == "critical"
    n = normalizer.normalize(_parsed(severity="Info"))
    assert n.severity == "low"


def test_normalize_status_stable(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.status == "stable"


def test_normalize_status_deprecated_flows_through(normalizer):
    """Parser stamps `status: deprecated` when RuleID is in deprecated.txt;
    normalizer preserves it through canonical normalization."""
    n = normalizer.normalize(_parsed(status="deprecated"))
    assert n.status == "deprecated"


def test_normalize_status_experimental_flows_through(normalizer):
    """Signal-only rules get status=experimental from the parser."""
    n = normalizer.normalize(_parsed(status="experimental"))
    assert n.status == "experimental"


def test_normalize_mitre_passthrough(normalizer):
    """Panther's colon-joined `TA####:T####` is parsed upstream — the
    normalizer just passes through the already-split arrays."""
    n = normalizer.normalize(_parsed())
    assert "TA0005" in n.mitre_tactics
    assert "T1562.008" in n.mitre_techniques


def test_normalize_source_rule_url_uses_develop_branch(normalizer):
    """Panther publishes on `develop`, not `main`/`master`."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "panther-labs/panther-analysis" in n.source_rule_url
    assert "/blob/develop/rules/" in n.source_rule_url


def test_normalize_runs_ast_extraction(normalizer):
    """The Python module is walked with ast (issue #6): field paths,
    comparison terms, and YAML LogTypes as source tables."""
    n = normalizer.normalize(_parsed())
    assert "eventName" in n.extracted_fields_used
    assert n.extracted_source_tables == ["AWS.CloudTrail"]
    obs = [o for o in n.extracted_observables if o["field"] == "eventName"]
    assert obs and obs[0]["values"] == ["StopLogging"]
    # eventName -> cloud api_action -> api_actions surface
    assert "StopLogging" in n.extracted_api_actions


def test_normalize_report_family_tags_preserved(normalizer):
    """Non-MITRE Reports families (CIS, Stratus Red Team) are preserved
    as `report:*` prefixed tags by the parser; the normalizer just
    passes tags through."""
    n = normalizer.normalize(_parsed())
    assert "report:cis" in n.tags
    assert "report:stratus_red_team" in n.tags


def test_normalize_references_pass_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.references == ["https://example.com/mitre-t1562-008"]
