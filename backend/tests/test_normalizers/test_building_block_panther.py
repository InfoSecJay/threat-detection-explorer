"""Panther / pypanther signal-only rules become building blocks (issue #26).

Before: `CreateAlert: false` or the `panther-signal` tag forced
status=experimental, conflating "feeds other rules" with "immature".
Now the parser records `is_signal_only`, the normalizer maps it to
`is_building_block`, and status comes from `Enabled` alone.
"""

from __future__ import annotations

from app.normalizers.panther import PantherNormalizer
from app.normalizers.pypanther import PyPantherNormalizer
from app.parsers.base import ParsedRule


def _parsed(source: str = "panther", **overrides) -> ParsedRule:
    defaults = dict(
        source=source,
        file_path="rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml",
        raw_content="AnalysisType: rule\nRuleID: AWS.CloudTrail.Stopped\n",
        title="CloudTrail Was Stopped",
        detection_logic_raw='def rule(event):\n    return event.get("eventName") == "StopLogging"\n',
        description="Detects StopLogging API calls.",
        author=None,
        status="stable",
        severity="High",
        log_source={"product": "aws", "category": None, "service": None},
        tags=["Defense Evasion:Impair Defenses"],
        mitre_attack={"tactics": ["TA0005"], "techniques": ["T1562.008"], "groups": [], "software": []},
        false_positives=[],
        extra={
            "id": "AWS.CloudTrail.Stopped",
            "display_name": "CloudTrail Was Stopped",
            "language": "python",
            "analysis_type": "rule",
            "log_types": ["AWS.CloudTrail"],
            "reference": [],
            "runbook": None,
            "dedup_period_minutes": 60,
            "threshold": 1,
            "create_alert": True,
            "enabled": True,
            "is_signal_only": False,
            "reports": {},
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


def _with_extra(parsed: ParsedRule, **extra) -> ParsedRule:
    return _parsed(
        source=parsed.source,
        file_path=parsed.file_path,
        status=parsed.status,
        extra=dict(parsed.extra, **extra),
    )


def test_panther_regular_rule():
    n = PantherNormalizer("https://github.com/panther-labs/panther-analysis").normalize(_parsed())
    assert n.is_building_block is False
    assert n.status == "stable"


def test_panther_signal_only_is_building_block_not_experimental():
    n = PantherNormalizer("https://github.com/panther-labs/panther-analysis").normalize(
        _with_extra(_parsed(), is_signal_only=True, create_alert=False)
    )
    assert n.is_building_block is True
    # Status is decided by Enabled, not by signal-only.
    assert n.status == "stable"


def test_panther_disabled_signal_only_is_experimental_and_building_block():
    n = PantherNormalizer("https://github.com/panther-labs/panther-analysis").normalize(
        _with_extra(_parsed(status="experimental"), is_signal_only=True, enabled=False)
    )
    assert n.is_building_block is True
    assert n.status == "experimental"


def test_pypanther_signal_only_flag():
    base = _parsed(source="pypanther", file_path="pypanther/rules/aws_cloudtrail/aws_cloudtrail_stopped.py")
    n = PyPantherNormalizer("https://github.com/panther-labs/pypanther").normalize(
        _with_extra(base, is_signal_only=True)
    )
    assert n.is_building_block is True
    n2 = PyPantherNormalizer("https://github.com/panther-labs/pypanther").normalize(base)
    assert n2.is_building_block is False
