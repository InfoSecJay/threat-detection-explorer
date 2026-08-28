"""Tests for the pypanther parser (issue #27).

Fixture mirrors a real pypanther rule module
(pypanther/rules/aws_cloudtrail/aws_cloudtrail_stopped.py).
"""

from pathlib import Path

import pytest

from app.parsers.pypanther import PyPantherParser

RULE_SRC = '''\
from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.aws import aws_cloudtrail_success, aws_rule_context


@panther_managed
class AWSCloudTrailStopped(Rule):
    id = "AWS.CloudTrail.Stopped-prototype"
    display_name = "CloudTrail Stopped"
    log_types = [LogType.AWS_CLOUDTRAIL]
    tags = ["AWS", "Security Control"]
    reports = {"CIS": ["3.5"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.MEDIUM
    default_description = "A CloudTrail Trail was modified.\\n"
    default_runbook = "https://docs.runpanther.io/alert-runbooks/built-in-rules/aws-cloudtrail-modified"
    default_reference = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-delete-trails-console.html"
    CLOUDTRAIL_STOP_DELETE = {"DeleteTrail", "StopLogging"}

    def rule(self, event):
        return aws_cloudtrail_success(event) and event.get("eventName") in self.CLOUDTRAIL_STOP_DELETE

    def title(self, event):
        return f"CloudTrail stopped in [{event.get('recipientAccountId')}]"
'''

RULE_PATH = Path("pypanther/rules/aws_cloudtrail/aws_cloudtrail_stopped.py")


@pytest.fixture
def parser():
    p = PyPantherParser()
    # No discovery service in tests — seed the enum map directly.
    p._log_type_map = {"AWS_CLOUDTRAIL": "AWS.CloudTrail"}
    return p


def test_can_parse_scope(parser):
    assert parser.can_parse(RULE_PATH)
    assert not parser.can_parse(Path("pypanther/rules/aws_cloudtrail/__init__.py"))
    assert not parser.can_parse(Path("pypanther/base.py"))
    assert not parser.can_parse(Path("rules/aws_cloudtrail_rules/x.yml"))


def test_parse_metadata(parser):
    r = parser.parse(RULE_PATH, RULE_SRC)
    assert r is not None
    assert r.source == "pypanther"
    assert r.title == "CloudTrail Stopped"
    assert r.extra["id"] == "AWS.CloudTrail.Stopped-prototype"
    assert r.severity == "medium"
    assert r.status == "stable"
    assert "AWS" in r.tags
    # Non-MITRE report families become report:* tags (panther parity).
    assert "report:cis" in r.tags


def test_logtype_enum_resolves_to_string_value(parser):
    r = parser.parse(RULE_PATH, RULE_SRC)
    assert r.extra["log_types"] == ["AWS.CloudTrail"]
    assert r.log_source["product"] == "aws"


def test_logtype_falls_back_to_attr_name_without_enum():
    p = PyPantherParser()
    p._log_type_map = {}
    r = p.parse(RULE_PATH, RULE_SRC)
    assert r.extra["log_types"] == ["AWS_CLOUDTRAIL"]


def test_mitre_split(parser):
    r = parser.parse(RULE_PATH, RULE_SRC)
    assert r.mitre_attack["tactics"] == ["TA0005"]
    assert r.mitre_attack["techniques"] == ["T1562"]


def test_detection_logic_is_whole_module(parser):
    r = parser.parse(RULE_PATH, RULE_SRC)
    assert r.detection_logic_raw == RULE_SRC
    assert 'event.get("eventName")' in r.detection_logic_raw


def test_helper_module_without_rule_class_is_skipped(parser):
    assert parser.parse(
        Path("pypanther/rules/aws_cloudtrail/helpers.py"),
        "def shared_helper(event):\n    return event\n",
    ) is None


def test_rule_class_without_id_is_skipped(parser):
    src = (
        "from pypanther import Rule\n"
        "class AbstractBase(Rule):\n"
        "    display_name = 'not a concrete rule'\n"
    )
    assert parser.parse(RULE_PATH, src) is None


def test_syntax_error_returns_none(parser):
    assert parser.parse(RULE_PATH, "def broken(:\n") is None


def test_enum_module_parsing():
    src = (
        "from enum import Enum\n"
        "class LogType(str, Enum):\n"
        "    AWS_CLOUDTRAIL = \"AWS.CloudTrail\"\n"
        "    OKTA_SYSTEM_LOG = \"Okta.SystemLog\"\n"
    )
    got = PyPantherParser._parse_log_type_enum(src)
    assert got == {
        "AWS_CLOUDTRAIL": "AWS.CloudTrail",
        "OKTA_SYSTEM_LOG": "Okta.SystemLog",
    }


def test_disabled_rule_is_experimental(parser):
    src = RULE_SRC.replace(
        'default_severity = Severity.MEDIUM',
        'default_severity = Severity.MEDIUM\n    enabled = False',
    )
    r = parser.parse(RULE_PATH, src)
    assert r.status == "experimental"
