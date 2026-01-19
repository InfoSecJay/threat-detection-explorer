"""Splunk Security Content detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class SplunkNormalizer(BaseNormalizer):
    """Normalizer for Splunk Security Content detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Splunk rule to normalized format."""
        extra = parsed.extra or {}

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="develop"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            log_sources=self._normalize_log_sources(parsed.log_source),
            data_sources=self._extract_data_sources(parsed),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            tags=self._normalize_tags(parsed.tags),
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=self.parse_date(extra.get("date")),
            rule_modified_date=None,  # Splunk doesn't have a modified date field
        )

    def _normalize_log_sources(self, log_source: dict) -> list[str]:
        """Extract normalized log sources from Splunk metadata."""
        sources = []

        product = log_source.get("product")
        if product:
            sources.append(product.lower())

        # Get from data sources
        data_sources = log_source.get("data_sources", [])
        for ds in data_sources:
            if ds:
                sources.append(ds.lower())

        return list(set(sources))

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Splunk rule."""
        raw_sources = []

        # Get explicit data sources from Splunk metadata
        data_sources = parsed.extra.get("data_source", [])
        for ds in data_sources:
            if ds:
                raw_sources.append(ds)

        # Infer from search query
        search = parsed.detection_logic_raw.get("search", "")
        if search:
            search_lower = search.lower()
            if "sysmon" in search_lower:
                raw_sources.append("sysmon")
            if "wineventlog" in search_lower:
                raw_sources.append("windows_event")
            if "security" in search_lower and "windows" in search_lower:
                raw_sources.append("security_event")
            if "powershell" in search_lower:
                raw_sources.append("powershell")
            if "registry" in search_lower:
                raw_sources.append("registry")
            if "process" in search_lower:
                raw_sources.append("process_creation")
            if "network" in search_lower:
                raw_sources.append("network")
            if "dns" in search_lower:
                raw_sources.append("dns")
            if "authentication" in search_lower or "logon" in search_lower:
                raw_sources.append("authentication")
            if "cloudtrail" in search_lower or "aws" in search_lower:
                raw_sources.append("aws")
            if "azure" in search_lower:
                raw_sources.append("azure")
            if "gcp" in search_lower or "google" in search_lower:
                raw_sources.append("gcp")

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Splunk SPL search for display.

        Args:
            detection: Detection logic dict with search

        Returns:
            The full search query
        """
        if not isinstance(detection, dict):
            return str(detection)

        search = detection.get("search", "")
        if not search:
            return "No search query defined"

        return search

    def _normalize_tags(self, tags: list) -> list[str]:
        """Normalize Splunk tags to consistent format."""
        normalized = []
        for tag in tags:
            if tag and isinstance(tag, str):
                # Remove prefixes like "story:", "asset:" for cleaner tags
                if ":" in tag:
                    prefix, value = tag.split(":", 1)
                    # Keep the value, lowercase and underscore-separated
                    normalized.append(value.lower().replace(" ", "_"))
                else:
                    normalized.append(tag.lower().replace(" ", "_"))
        return normalized
