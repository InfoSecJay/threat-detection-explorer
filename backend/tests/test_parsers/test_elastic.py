"""Tests for Elastic parser."""

from pathlib import Path
import pytest
from app.parsers.elastic import ElasticParser
from tests.conftest import SAMPLE_ELASTIC_RULE


class TestElasticParser:
    """Tests for ElasticParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = ElasticParser()

    def test_source_name(self):
        """Test parser source name."""
        assert self.parser.source_name == "elastic"

    def test_can_parse_valid_path(self):
        """Test can_parse with valid Elastic rule path."""
        valid_paths = [
            Path("rules/windows/test.toml"),
            Path("rules/linux/persistence/test.toml"),
            Path("rules/cross-platform/test.toml"),
        ]
        for path in valid_paths:
            assert self.parser.can_parse(path), f"Should parse: {path}"

    def test_can_parse_invalid_path(self):
        """Test can_parse with invalid paths."""
        invalid_paths = [
            Path("_deprecated/old_rule.toml"),
            Path("tests/test_rule.toml"),
            Path("rules/test.yml"),
            Path("_building_block/test.toml"),
        ]
        for path in invalid_paths:
            assert not self.parser.can_parse(path), f"Should not parse: {path}"

    def test_parse_valid_rule(self):
        """Test parsing a valid Elastic rule."""
        result = self.parser.parse(
            Path("rules/windows/test.toml"),
            SAMPLE_ELASTIC_RULE
        )

        assert result is not None
        assert result.source == "elastic"
        assert result.title == "Suspicious PowerShell Execution"
        assert "suspicious PowerShell execution" in result.description.lower()
        assert result.severity == "high"
        assert result.status == "stable"  # production -> stable
        assert "T1059" in result.mitre_attack.get("techniques", [])

    def test_parse_missing_name(self):
        """Test parsing rule without name returns None."""
        rule_without_name = '''
[metadata]
creation_date = "2023/01/01"

[rule]
description = "Test rule"
type = "query"
query = "test"
'''
        result = self.parser.parse(Path("rules/test.toml"), rule_without_name)
        assert result is None

    def test_parse_missing_query(self):
        """Test parsing rule without query returns None."""
        rule_without_query = '''
[metadata]
creation_date = "2023/01/01"

[rule]
name = "Test Rule"
description = "Test"
type = "query"
'''
        result = self.parser.parse(Path("rules/test.toml"), rule_without_query)
        assert result is None

    def test_parse_malformed_toml(self):
        """Test parsing malformed TOML returns None."""
        malformed = '''
[rule]
name = "Test
'''
        result = self.parser.parse(Path("rules/test.toml"), malformed)
        assert result is None

    def test_maturity_to_status_mapping(self):
        """Test maturity field is mapped to status correctly."""
        template = '''
[metadata]
maturity = "{maturity}"

[rule]
name = "Test Rule"
type = "query"
query = "test"
'''
        mappings = {
            "production": "stable",
            "development": "experimental",
            "deprecated": "deprecated",
        }

        for maturity, expected_status in mappings.items():
            rule = template.format(maturity=maturity)
            result = self.parser.parse(Path("rules/test.toml"), rule)
            assert result is not None
            assert result.status == expected_status, f"Expected {expected_status} for maturity {maturity}"
