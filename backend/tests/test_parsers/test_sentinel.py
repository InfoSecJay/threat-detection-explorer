"""Tests for Sentinel parser -- focused on the None-in-YAML class of bugs
and the technique -> tactic inference wiring.
"""

from pathlib import Path

from app.parsers.sentinel import SentinelParser


class TestSentinelNoneSafety:
    """Sentinel Solutions rules like Darktrace's CreateAlertFromModelBreach
    declare `tactics:` / `relevantTechniques:` with no value (a common
    'filled in dynamically' comment convention). YAML parses those as
    Python None. dict.get(k, [])'s default only fires when k is ABSENT
    -- present-but-None returns None, and iterating None crashes.

    Pre-fix: 8 upstream Sentinel Solutions rules silently dropped this
    way (Darktrace, Jamf Protect, IronDefense, Trend Micro Vision One,
    Radiflow, Valence Security). Post-fix: they parse cleanly.
    """

    def setup_method(self):
        self.parser = SentinelParser()

    def test_tactics_null_in_yaml_does_not_crash(self):
        """Reproduces the CreateAlertFromModelBreach.yaml shape."""
        rule = """
id: a3c7b8ed-56a9-47b7-98e5-2555c16e17c9
name: Darktrace Model Breach
description: test
severity: Medium
tactics: # tactics pulled dynamically
relevantTechniques:
query: |
  DarktraceModelAlerts_CL | where ProductType == "Policy Breach"
"""
        result = self.parser.parse(
            Path("Solutions/Darktrace/Analytic Rules/x.yaml"), rule
        )
        assert result is not None, "parser must not drop rules with null tactics"
        assert result.title == "Darktrace Model Breach"
        assert result.mitre_attack.get("tactics") == []
        assert result.mitre_attack.get("techniques") == []

    def test_tactic_inference_from_technique_only_rules(self):
        """When a rule ships `relevantTechniques` but no `tactics`, the
        tactic list must be inferred from the MITRE cache so the site
        still shows a tactic on the rule detail page. Uses T1059
        which maps to TA0002 in the canonical STIX bundle."""
        rule = """
id: e0e0e0e0-0000-0000-0000-000000000000
name: Technique Only
description: test
severity: Medium
relevantTechniques:
  - T1059
query: |
  SigninLogs | where ResultType != 0
"""
        result = self.parser.parse(
            Path("Solutions/Test/Analytic Rules/x.yaml"), rule
        )
        assert result is not None
        assert "T1059" in result.mitre_attack.get("techniques", [])
        # T1059 -> Execution (TA0002) in the canonical MITRE map.
        assert "TA0002" in result.mitre_attack.get("tactics", [])

    def test_explicit_tactics_win_over_inference(self):
        """If a rule ships BOTH explicit tactics and techniques, the
        explicit values must be preserved and inference only adds
        (never replaces)."""
        rule = """
id: e0e0e0e0-0000-0000-0000-000000000001
name: Both Provided
description: test
severity: Medium
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |
  test
"""
        result = self.parser.parse(
            Path("Solutions/Test/Analytic Rules/x.yaml"), rule
        )
        assert result is not None
        # Only TA0002 -- explicit tactic + inference agree, no dupes.
        assert result.mitre_attack.get("tactics") == ["TA0002"]


class TestSentinelStatusDefault:
    """Azure-Sentinel templates carry no maturity field. They are
    published as production content, so the default is `stable` like
    every other no-maturity-concept source (#47), not `unknown`."""

    def setup_method(self):
        self.parser = SentinelParser()

    def test_missing_status_defaults_to_stable(self):
        rule = """
id: 11111111-0000-0000-0000-000000000000
name: No Status
description: test
severity: Medium
query: |
  SigninLogs | where ResultType != 0
"""
        result = self.parser.parse(Path("Solutions/Test/Analytic Rules/x.yaml"), rule)
        assert result is not None
        assert result.status == "stable"

    def test_explicit_status_is_preserved(self):
        rule = """
id: 22222222-0000-0000-0000-000000000000
name: Has Status
description: test
severity: Medium
status: experimental
query: |
  SigninLogs | where ResultType != 0
"""
        result = self.parser.parse(Path("Solutions/Test/Analytic Rules/x.yaml"), rule)
        assert result is not None
        assert result.status == "experimental"
