"""Stubs and non-rules are skips, not parse failures (#58), and the
Panther RuleID prefix fallback (#57)."""

from __future__ import annotations

from pathlib import Path

from app.parsers.base import ParsedRule, SkippedRule
from app.parsers.sentinel import SentinelParser
from app.services.taxonomy.vendors import panther as panther_taxonomy

MOVED = """id: 7569d97b-6166-4d7c-82a4-73fb2a53c0ed
name: TI map IP entity to DnsEvents
description: |
    'As part of content migration, this file is moved to new location. you can find here: https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_DnsEvents.yaml'
version: 1.0.1
"""

RETIRED = """id: 04384937-e927-4595-8f3c-89ff58ed231f
name: Possible Forest Blizzard attempted credential harvesting - Sept 2020
description: |
  This analytic rule is retired because IoCs are outdated. It is recommended to use Microsoft Entra ID Solution's Analytic rules instead.
version: 3.0.0
"""

REAL = """id: 1111
name: Real rule
description: A rule.
severity: Medium
kind: Scheduled
query: SecurityEvent | where EventID == 4688
tactics: [Execution]
"""

HUNTING = REAL.replace("kind: Scheduled", "kind: Hunting")


def test_sentinel_stubs_are_skipped_not_failed():
    p = SentinelParser()
    moved = p.parse(Path("Detections/x.yaml"), MOVED)
    retired = p.parse(Path("Solutions/y.yaml"), RETIRED)
    assert isinstance(moved, SkippedRule) and "stub" in moved.reason
    assert isinstance(retired, SkippedRule)


def test_sentinel_real_rule_and_hunting_kind():
    p = SentinelParser()
    real = p.parse(Path("Solutions/r.yaml"), REAL)
    assert isinstance(real, ParsedRule) and real.title == "Real rule"
    hunting = p.parse(Path("Solutions/h.yaml"), HUNTING)
    assert isinstance(hunting, SkippedRule) and "Hunting" in hunting.reason


def test_sentinel_truly_broken_file_is_still_a_failure():
    assert SentinelParser().parse(Path("x.yaml"), "name: Broken\nseverity: Low\n") is None


def test_panther_rule_id_prefix_fallback():
    parsed = ParsedRule(
        source="panther", file_path="rules/auth0_rules/auth0_brute_force.yml", raw_content="",
        title="Auth0 Brute Force", detection_logic_raw="", extra={"log_types": [], "rule_id": "Auth0.Brute.Force"},
    )
    out = panther_taxonomy.resolve(parsed)
    assert "auth0" in out["platforms"]
    assert "auth0_logs" in out["data_sources"]
