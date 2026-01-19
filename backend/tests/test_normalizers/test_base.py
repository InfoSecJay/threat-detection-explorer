"""Tests for base normalizer."""

import pytest
from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class ConcreteNormalizer(BaseNormalizer):
    """Concrete implementation for testing abstract base class."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            log_sources=self.normalize_log_sources(parsed.log_source),
            data_sources=[],
            mitre_tactics=[],
            mitre_techniques=[],
            detection_logic="",
            tags=[],
            raw_content=parsed.raw_content,
        )


class TestBaseNormalizer:
    """Tests for BaseNormalizer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ConcreteNormalizer("https://example.com/repo")

    def test_generate_id_deterministic(self):
        """Test that ID generation is deterministic."""
        id1 = self.normalizer.generate_id("sigma", "rules/test.yml")
        id2 = self.normalizer.generate_id("sigma", "rules/test.yml")
        assert id1 == id2

    def test_generate_id_unique(self):
        """Test that different inputs produce different IDs."""
        id1 = self.normalizer.generate_id("sigma", "rules/test1.yml")
        id2 = self.normalizer.generate_id("sigma", "rules/test2.yml")
        id3 = self.normalizer.generate_id("elastic", "rules/test1.yml")
        assert id1 != id2
        assert id1 != id3

    def test_generate_id_format(self):
        """Test that ID follows UUID-like format."""
        id = self.normalizer.generate_id("sigma", "rules/test.yml")
        parts = id.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_normalize_status(self):
        """Test status normalization."""
        assert self.normalizer.normalize_status("stable") == "stable"
        assert self.normalizer.normalize_status("production") == "stable"
        assert self.normalizer.normalize_status("experimental") == "experimental"
        assert self.normalizer.normalize_status("development") == "experimental"
        assert self.normalizer.normalize_status("deprecated") == "deprecated"
        assert self.normalizer.normalize_status("unknown_status") == "unknown"
        assert self.normalizer.normalize_status(None) == "unknown"
        assert self.normalizer.normalize_status("") == "unknown"

    def test_normalize_severity(self):
        """Test severity normalization."""
        assert self.normalizer.normalize_severity("low") == "low"
        assert self.normalizer.normalize_severity("informational") == "low"
        assert self.normalizer.normalize_severity("medium") == "medium"
        assert self.normalizer.normalize_severity("moderate") == "medium"
        assert self.normalizer.normalize_severity("high") == "high"
        assert self.normalizer.normalize_severity("critical") == "critical"
        assert self.normalizer.normalize_severity("severe") == "critical"
        assert self.normalizer.normalize_severity("unknown_sev") == "unknown"
        assert self.normalizer.normalize_severity(None) == "unknown"

    def test_normalize_log_sources(self):
        """Test log source normalization."""
        log_source = {
            "product": "Windows",
            "category": "process_creation",
            "service": "sysmon",
        }
        result = self.normalizer.normalize_log_sources(log_source)
        assert "windows" in result
        assert "process_creation" in result
        assert "sysmon" in result

    def test_normalize_log_sources_dedup(self):
        """Test that log sources are deduplicated."""
        log_source = {
            "product": "windows",
            "category": "windows",  # Duplicate
        }
        result = self.normalizer.normalize_log_sources(log_source)
        assert result.count("windows") == 1

    def test_normalize_log_sources_empty(self):
        """Test normalization of empty log source."""
        result = self.normalizer.normalize_log_sources({})
        assert result == []
