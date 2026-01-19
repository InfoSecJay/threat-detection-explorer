"""Tests for Splunk parser."""

from pathlib import Path
import pytest
from app.parsers.splunk import SplunkParser
from tests.conftest import SAMPLE_SPLUNK_RULE


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
        assert "suspicious PowerShell" in result.description.lower()
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
