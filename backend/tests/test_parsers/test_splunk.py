"""Tests for Splunk parser."""

from pathlib import Path
import pytest
from app.parsers.splunk import SplunkParser
from tests.conftest import SAMPLE_SPLUNK_RULE


# A real-world sample of the CURRENT (2025-2026) Splunk security-content
# schema. Key differences from the legacy schema exercised in
# SAMPLE_SPLUNK_RULE:
#   - No `tags:` block at all -- everything hoisted to top level
#   - `mitre_attack_id`, `security_domain`, `asset_type`, `analytic_story`,
#     `product`, `category` all live at TOP LEVEL
#   - `creation_date` / `modification_date` replace `date`
#   - Severity comes from `finding.entity.score` instead of `rba` or
#     `tags.impact`/`tags.confidence`
# Source: windows_powgoop_beacon_decoding.yml in splunk/security_content
NEW_SCHEMA_SPLUNK_RULE = """
name: Windows PowGoop Beacon Decoding
id: 4d0480d8-80c4-4f74-84fe-2ab7fb514c85
version: 2
creation_date: '2026-05-05'
modification_date: '2026-05-13'
author: Raven Tait, Splunk
status: production
type: TTP
description: Detects DLL decoding and executing the PowGoop config.txt payload.
data_source:
    - Sysmon EventID 1
search: |-
    | tstats count from datamodel=Endpoint.Processes
    where Processes.parent_process_path="*rundll32.exe"
finding:
    title: Potential PowGoop Beacon Decoding activity observed.
    entity:
        field: dest
        type: system
        score: 50
analytic_story:
    - Compromised Windows Host
asset_type: Endpoint
mitre_attack_id:
    - T1059.001
    - T1001
product:
    - Splunk Enterprise
category: endpoint
security_domain: endpoint
"""


class TestSplunkParser:
    """Tests for SplunkParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SplunkParser()

    def test_source_name(self):
        """Test parser source name."""
        assert self.parser.source_name == "splunk"

    def test_can_parse_valid_path(self):
        """Test can_parse with valid Splunk detection path."""
        valid_paths = [
            Path("detections/endpoint/test.yml"),
            Path("detections/cloud/aws/test.yaml"),
            Path("detections/network/test.yml"),
        ]
        for path in valid_paths:
            assert self.parser.can_parse(path), f"Should parse: {path}"

    def test_can_parse_invalid_path(self):
        """Test can_parse with invalid paths."""
        invalid_paths = [
            Path("deprecated/old_detection.yml"),
            Path("tests/test_detection.yml"),
            Path("detections/test.toml"),
            Path("rules/test.yml"),  # Not detections directory
        ]
        for path in invalid_paths:
            assert not self.parser.can_parse(path), f"Should not parse: {path}"

    def test_parse_valid_rule(self):
        """Test parsing a valid Splunk detection."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"),
            SAMPLE_SPLUNK_RULE
        )

        assert result is not None
        assert result.source == "splunk"
        assert result.title == "Suspicious PowerShell Command"
        assert "suspicious powershell" in result.description.lower()
        assert result.author == "Test Author"
        assert "T1059.001" in result.mitre_attack.get("techniques", [])

    def test_parse_missing_name(self):
        """Test parsing detection without name returns None."""
        rule_without_name = """
description: Test detection
search: |
  | tstats count from datamodel=Endpoint.Processes
"""
        result = self.parser.parse(Path("detections/test.yml"), rule_without_name)
        assert result is None

    def test_parse_missing_search(self):
        """Test parsing detection without search returns None."""
        rule_without_search = """
name: Test Detection
description: Test
"""
        result = self.parser.parse(Path("detections/test.yml"), rule_without_search)
        assert result is None

    def test_parse_malformed_yaml(self):
        """Test parsing malformed YAML returns None."""
        malformed = """
name: Test
search: [unclosed
"""
        result = self.parser.parse(Path("detections/test.yml"), malformed)
        assert result is None

    # ── New-schema tests (top-level fields, no `tags:` block) ────────

    def test_new_schema_extracts_mitre_techniques(self):
        """Regression test for the PowGoop bug: mitre_attack_id at the
        TOP LEVEL of the YAML (no tags: block) must still be extracted."""
        result = self.parser.parse(
            Path("detections/endpoint/windows_powgoop_beacon_decoding.yml"),
            NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        techs = result.mitre_attack.get("techniques", [])
        assert "T1059.001" in techs
        assert "T1001" in techs

    def test_new_schema_infers_mitre_tactic_from_technique(self):
        """T1059.001 -> TA0002 (Execution) should be inferred even when
        kill_chain_phases isn't present."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"), NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        assert "TA0002" in result.mitre_attack.get("tactics", [])

    def test_new_schema_extracts_analytic_story_from_top_level(self):
        """analytic_story at top level (not under tags:) must surface
        as a story: tag so the Threat Pulse feature keeps working."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"), NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        assert any(t.startswith("story:") for t in result.tags), (
            f"Expected a story: tag; got {result.tags}"
        )

    def test_new_schema_security_domain_from_top_level(self):
        """security_domain at top level must populate extra so the
        taxonomy resolver's Tier 4 fallback works."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"), NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        assert result.extra.get("security_domain") == "endpoint"

    def test_new_schema_severity_from_finding_entity_score(self):
        """finding.entity.score=50 -> medium (40-59 bucket) via
        synthetic rba mapping."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"), NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        assert result.severity == "medium"

    def test_new_schema_creation_date_fallback(self):
        """When `date:` is absent, `creation_date:` must be used as the
        rule-created source so the normalizer's date resolver gets a
        real value instead of falling back to git log."""
        result = self.parser.parse(
            Path("detections/endpoint/test.yml"), NEW_SCHEMA_SPLUNK_RULE,
        )
        assert result is not None
        assert result.extra.get("date") == "2026-05-05"
        assert result.extra.get("modification_date") == "2026-05-13"

    def test_old_schema_still_wins_on_conflict(self):
        """If a rule mid-migration populates BOTH tags.mitre_attack_id
        AND top-level mitre_attack_id, the nested (historically
        authoritative) value must win -- we don't want the new-schema
        promotion to silently override an existing nested value."""
        mixed = """
name: Mixed Schema
search: test
tags:
  mitre_attack_id:
    - T9999   # nested value
mitre_attack_id:
  - T1059     # top-level value; should be ignored
"""
        result = self.parser.parse(Path("detections/x.yml"), mixed)
        assert result is not None
        techs = result.mitre_attack.get("techniques", [])
        assert "T9999" in techs
        assert "T1059" not in techs

    def test_severity_from_intermediate_findings(self):
        """Anomaly rules carry the risk score under
        intermediate_findings.entities[].score -- 20 -> low."""
        rule = """
name: Add DefaultUser And Password In Registry
search: test
type: Anomaly
intermediate_findings:
    entities:
        - field: dest
          type: system
          score: 20
          message: modified registry key
"""
        result = self.parser.parse(Path("detections/endpoint/test.yml"), rule)
        assert result is not None
        assert result.severity == "low"

    def test_severity_correlation_score_zero_maps_high(self):
        """Correlation rules ship finding.entity.score: 0 (they consume
        aggregated risk, not produce it). They're high-fidelity Risk
        Notable alerts -> high, not low/unknown."""
        rule = """
name: Active Directory Lateral Movement Identified
search: test
type: Correlation
finding:
    title: Lateral movement - $risk_object$
    entity:
        field: risk_object
        type: system
        score: 0
"""
        result = self.parser.parse(Path("detections/endpoint/test.yml"), rule)
        assert result is not None
        assert result.severity == "high"

    def test_severity_hunting_without_score_is_not_fabricated(self):
        """Hunting rules ship no risk score by design. That is absence
        of signal, not low severity -- presenting a default as data is
        the failure mode teardown R08 called out (#106)."""
        rule = """
name: 7zip CommandLine To SMB Share Path
search: test
type: Hunting
"""
        result = self.parser.parse(Path("detections/endpoint/test.yml"), rule)
        assert result is not None
        assert result.severity == "unknown"

    def test_severity_scoreless_rule_is_unknown(self):
        """A rule with no score signal anywhere surfaces `unknown`
        (rendered "Not specified"), a first-class facet value -- never
        a fabricated level (teardown R08 / #106)."""
        rule = """
name: Bare Minimum Rule
search: test
"""
        result = self.parser.parse(Path("detections/test.yml"), rule)
        assert result is not None
        assert result.severity == "unknown"

    def test_severity_derivation(self):
        """Test severity is derived from confidence and impact."""
        template = """
name: Test Detection
search: test
tags:
  confidence: {confidence}
  impact: {impact}
"""
        # High confidence + high impact = critical
        rule = template.format(confidence=90, impact=90)
        result = self.parser.parse(Path("detections/test.yml"), rule)
        assert result is not None
        assert result.severity == "critical"

        # Medium values
        rule = template.format(confidence=50, impact=50)
        result = self.parser.parse(Path("detections/test.yml"), rule)
        assert result is not None
        assert result.severity == "medium"

        # Low values
        rule = template.format(confidence=20, impact=20)
        result = self.parser.parse(Path("detections/test.yml"), rule)
        assert result is not None
        assert result.severity == "low"
