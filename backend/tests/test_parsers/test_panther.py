"""Tests for PantherParser.

Focus on the shapes that only the parser handles:
- YAML metadata parsing (RuleID, DisplayName, LogTypes, Reports, Tags,
  Severity, DedupPeriodMinutes, Threshold, CreateAlert)
- .py sibling loading via a stub discovery service
- Correlation + declarative rules with no .py sibling — YAML Detection
  block serialized as detection_logic
- Panther-specific MITRE tag format (`TA####:T####`)
- Non-MITRE report families as `report:*` prefixed tags
- Signal-only rules (`CreateAlert: false` or `panther-signal` tag)
  stamped `experimental`
- Deprecated rules stamped from `deprecated.txt`
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from app.parsers.panther import PantherParser


class StubDiscovery:
    """Minimal RuleDiscoveryService stand-in for parser tests.

    Two knobs: `siblings` maps `rel_path -> content` for
    get_sibling_content lookups; `deprecated_txt` supplies the
    optional deprecated.txt content.
    """

    def __init__(self, siblings: Optional[dict[str, str]] = None, deprecated_txt: str = ""):
        self.siblings = siblings or {}
        self.deprecated_txt = deprecated_txt

    def get_sibling_content(self, repo_name: str, rel_path: Path, extension: str) -> Optional[str]:
        assert repo_name == "panther"
        key = str(rel_path.with_suffix(extension)).replace("\\", "/")
        return self.siblings.get(key)

    def get_rule_content(self, repo_name: str, rel_path: Path) -> Optional[str]:
        # Used by the parser only for `deprecated.txt`.
        if str(rel_path).replace("\\", "/") == "deprecated.txt":
            return self.deprecated_txt
        return None


# ── Sample rule fixtures (real Panther metadata shapes) ────────────

_SAMPLE_YAML = """\
AnalysisType: rule
RuleID: AWS.CloudTrail.Stopped
Filename: aws_cloudtrail_stopped.py
DisplayName: CloudTrail Was Stopped
Enabled: true
LogTypes:
  - AWS.CloudTrail
Severity: High
CreateAlert: true
DedupPeriodMinutes: 60
Threshold: 1
Description: Detects StopLogging API calls that turn off CloudTrail.
Reference: https://example.com/mitre-t1562-008
Runbook: Investigate the actor.
Tags:
  - Defense Evasion:Impair Defenses
Reports:
  MITRE ATT&CK:
    - TA0005:T1562.008
  CIS:
    - 3.5
  Stratus Red Team:
    - aws.defense-evasion.cloudtrail-stop
"""

_SAMPLE_PY = """\
def rule(event):
    return event.get("eventName") == "StopLogging"
"""


def _rel(name: str) -> Path:
    return Path("rules/aws_cloudtrail_rules") / name


def test_parse_standard_rule_with_py_sibling():
    """Standard rule: YAML metadata + .py sibling both surface."""
    disco = StubDiscovery(siblings={
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY,
    })
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), _SAMPLE_YAML)

    assert parsed is not None
    assert parsed.title == "CloudTrail Was Stopped"
    assert parsed.severity == "High"
    assert parsed.extra["id"] == "AWS.CloudTrail.Stopped"
    assert parsed.extra["language"] == "python"
    assert parsed.extra["analysis_type"] == "rule"
    assert parsed.extra["log_types"] == ["AWS.CloudTrail"]
    assert 'event.get("eventName") == "StopLogging"' in parsed.detection_logic_raw
    assert parsed.log_source["product"] == "aws"


def test_parse_mitre_tag_split_at_colon():
    """Panther's `TA####:T####` format splits into tactics + techniques."""
    disco = StubDiscovery(siblings={
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY,
    })
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), _SAMPLE_YAML)

    assert "TA0005" in parsed.mitre_attack["tactics"]
    assert "T1562.008" in parsed.mitre_attack["techniques"]
    # Panther doesn't tag groups/software via this field
    assert parsed.mitre_attack["groups"] == []
    assert parsed.mitre_attack["software"] == []


def test_parse_non_mitre_reports_become_report_prefixed_tags():
    """CIS + Stratus Red Team should become `report:cis` + `report:stratus_red_team`."""
    disco = StubDiscovery(siblings={
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY,
    })
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), _SAMPLE_YAML)

    assert "report:cis" in parsed.tags
    assert "report:stratus_red_team" in parsed.tags
    # MITRE ATT&CK is NOT re-added as a tag (it's already captured
    # in mitre_attack); only non-MITRE families get the prefix.
    assert "report:mitre_att&ck" not in parsed.tags
    # Original base tag preserved
    assert "Defense Evasion:Impair Defenses" in parsed.tags


def test_parse_signal_only_via_create_alert_false():
    """CreateAlert: false -> status: experimental + signal flag."""
    yaml_source = _SAMPLE_YAML.replace("CreateAlert: true", "CreateAlert: false")
    disco = StubDiscovery(siblings={
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY,
    })
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), yaml_source)

    assert parsed.status == "experimental"
    assert parsed.extra["is_signal_only"] is True


def test_parse_signal_only_via_panther_signal_tag():
    """Tag `panther-signal` -> same treatment."""
    yaml_source = _SAMPLE_YAML.replace(
        "Tags:\n  - Defense Evasion:Impair Defenses",
        "Tags:\n  - Defense Evasion:Impair Defenses\n  - panther-signal",
    )
    disco = StubDiscovery(siblings={
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY,
    })
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), yaml_source)

    assert parsed.status == "experimental"
    assert parsed.extra["is_signal_only"] is True


def test_parse_deprecated_rule_via_deprecated_txt():
    """RuleID in deprecated.txt -> status: deprecated."""
    disco = StubDiscovery(
        siblings={"rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py": _SAMPLE_PY},
        deprecated_txt="AWS.CloudTrail.Stopped\nSome.Other.Retired.Rule\n",
    )
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("aws_cloudtrail_stopped.yml"), _SAMPLE_YAML)

    assert parsed.status == "deprecated"


def test_parse_correlation_rule_without_py():
    """AnalysisType: correlation_rule + no .py sibling -> YAML
    Detection block serialized as detection_logic; language flag set."""
    yaml_source = """\
AnalysisType: correlation_rule
RuleID: AWS.CloudTrail.SESEnumeration
DisplayName: SES Enumeration (Correlated)
Severity: Medium
Detection:
  - Group:
      - RuleID: AWS.CloudTrail.SESListIdentities
      - RuleID: AWS.CloudTrail.SESGetSendQuota
"""
    disco = StubDiscovery()  # no .py siblings at all
    parser = PantherParser(disco)
    parsed = parser.parse(
        _rel("aws_cloudtrail_ses_enumeration.yml"),
        yaml_source,
    )
    assert parsed is not None
    assert parsed.extra["analysis_type"] == "correlation_rule"
    assert parsed.extra["language"] == "panther_correlation"
    # Detection block serialized to YAML string
    assert "SESListIdentities" in parsed.detection_logic_raw
    # No LogTypes on correlation rules
    assert parsed.extra["log_types"] == []


def test_parse_declarative_rule_without_py():
    """`AnalysisType: rule` with inline Detection block (no .py) —
    the one github_repo_archived shape."""
    yaml_source = """\
AnalysisType: rule
RuleID: Github.Repo.Archived
DisplayName: GitHub Repo Archived
Severity: Info
LogTypes:
  - GitHub.Audit
CreateAlert: false
Tags:
  - panther-signal
Detection:
  - KeyPath: action
    Condition: Equals
    Value: repo.archived
"""
    disco = StubDiscovery()
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("github_repo_archived.yml"), yaml_source)

    assert parsed is not None
    assert parsed.extra["language"] == "panther"
    assert "repo.archived" in parsed.detection_logic_raw


def test_parse_missing_title_returns_none():
    """A YAML with neither DisplayName nor RuleID isn't a rule."""
    disco = StubDiscovery()
    parser = PantherParser(disco)
    parsed = parser.parse(
        _rel("weird.yml"),
        "AnalysisType: rule\nSomeOtherKey: value\n",
    )
    assert parsed is None


def test_parse_malformed_yaml_returns_none():
    disco = StubDiscovery()
    parser = PantherParser(disco)
    parsed = parser.parse(_rel("broken.yml"), "not: valid: yaml: here: [\n")
    assert parsed is None


def test_can_parse_only_yaml_under_rules():
    parser = PantherParser()
    assert parser.can_parse(Path("rules/aws_cloudtrail_rules/x.yml")) is True
    assert parser.can_parse(Path("rules/aws_cloudtrail_rules/x.yaml")) is True
    # .py siblings — discovery doesn't yield them, but be defensive.
    assert parser.can_parse(Path("rules/aws_cloudtrail_rules/x.py")) is False
    # Outside rules/
    assert parser.can_parse(Path("policies/aws_config.yml")) is False


def test_deprecated_txt_ignores_prose_lines():
    """deprecated.txt has a mix of RuleIDs + prose descriptions.
    Only lines that look like RuleIDs (dotted, no whitespace) are
    treated as exclusions to avoid false positives."""
    disco = StubDiscovery(
        deprecated_txt=(
            "AWS.CloudTrail.Stopped\n"
            "Some free-form prose about retirement\n"
            "Okta.AdminRoleAssigned\n"
        ),
    )
    parser = PantherParser(disco)
    ids = parser._load_deprecated_ids()
    assert "AWS.CloudTrail.Stopped" in ids
    assert "Okta.AdminRoleAssigned" in ids
    # Prose line ignored
    assert not any(" " in i for i in ids)


def test_mitre_extractor_rejects_malformed_entries():
    """Non-`TA####:T####` items in Reports.MITRE ATT&CK are silently
    dropped instead of polluting the tactic/technique arrays."""
    parser = PantherParser()
    result = parser._extract_mitre([
        "TA0005:T1562.008",       # ok
        "TA0005",                  # missing technique — reject
        "T1562.008",               # missing tactic — reject
        "NotAnAttackID",           # junk — reject
        "TA0006:T1003",            # ok, no sub-technique
    ])
    assert result["tactics"] == ["TA0005", "TA0006"]
    assert result["techniques"] == ["T1562.008", "T1003"]
