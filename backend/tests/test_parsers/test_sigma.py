"""Tests for Sigma parser."""

from pathlib import Path
import pytest
from app.parsers.sigma import SigmaParser
from tests.conftest import SAMPLE_SIGMA_RULE


class TestSigmaParser:
    """Tests for SigmaParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SigmaParser()

    def test_source_name(self):
        """Test parser source name."""
        assert self.parser.source_name == "sigma"

    def test_can_parse_valid_path(self):
        """Test can_parse with valid Sigma rule path."""
        valid_paths = [
            Path("rules/windows/process_creation/test.yml"),
            Path("rules/linux/auditd/test.yaml"),
            Path("rules-windows/test.yml"),
        ]
        for path in valid_paths:
            assert self.parser.can_parse(path), f"Should parse: {path}"

    def test_can_parse_invalid_path(self):
        """Test can_parse with invalid paths."""
        invalid_paths = [
            Path("tests/test_rule.yml"),
            Path("deprecated/old_rule.yml"),
            Path("docs/readme.md"),
            Path("rules/test.toml"),
        ]
        for path in invalid_paths:
            assert not self.parser.can_parse(path), f"Should not parse: {path}"

    def test_parse_valid_rule(self):
        """Test parsing a valid Sigma rule."""
        result = self.parser.parse(
            Path("rules/windows/test.yml"),
            SAMPLE_SIGMA_RULE
        )

        assert result is not None
        assert result.source == "sigma"
        assert result.title == "Suspicious PowerShell Command Line"
        assert result.description == "Detects suspicious PowerShell command line arguments"
        assert result.author == "Test Author"
        assert result.status == "stable"
        assert result.severity == "high"
        assert "windows" in result.log_source.get("product", "")
        assert "T1059.001" in result.mitre_attack.get("techniques", [])
        assert "TA0002" in result.mitre_attack.get("tactics", [])  # execution

    def test_parse_missing_title(self):
        """Test parsing rule without title returns None."""
        rule_without_title = """
status: stable
detection:
    selection:
        CommandLine: test
    condition: selection
"""
        result = self.parser.parse(Path("rules/test.yml"), rule_without_title)
        assert result is None

    def test_parse_missing_detection(self):
        """Test parsing rule without detection returns None."""
        rule_without_detection = """
title: Test Rule
status: stable
"""
        result = self.parser.parse(Path("rules/test.yml"), rule_without_detection)
        assert result is None

    def test_parse_malformed_yaml(self):
        """Test parsing malformed YAML returns None."""
        malformed = """
title: Test
detection: [unclosed bracket
"""
        result = self.parser.parse(Path("rules/test.yml"), malformed)
        assert result is None

    def test_mitre_extraction_from_tags(self):
        """Test MITRE ATT&CK extraction from tags."""
        rule = """
title: Test Rule
detection:
    selection:
        test: value
    condition: selection
tags:
    - attack.execution
    - attack.t1059
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
"""
        result = self.parser.parse(Path("rules/test.yml"), rule)

        assert result is not None
        tactics = result.mitre_attack.get("tactics", [])
        techniques = result.mitre_attack.get("techniques", [])

        assert "TA0002" in tactics  # execution
        assert "TA0005" in tactics  # defense_evasion
        assert "T1059" in techniques
        assert "T1059.001" in techniques
        assert "T1027" in techniques
