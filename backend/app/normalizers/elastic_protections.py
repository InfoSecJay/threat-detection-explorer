"""Elastic Protection Artifacts detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class ElasticProtectionsNormalizer(BaseNormalizer):
    """Normalizer for Elastic Protection Artifacts detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Elastic Protections rule to normalized format."""
        extra = parsed.extra or {}
        log_source = parsed.log_source or {}

        # Extract log source fields for taxonomy
        product = log_source.get("product", "")
        category = log_source.get("category", "")

        # Get log sources
        log_sources_list = self.normalize_log_sources(log_source)

        # Apply taxonomy standardization
        platform, event_category, data_source_normalized = self.apply_log_source_taxonomy(
            log_sources=log_sources_list,
            product=product,
            category=category
        )

        # Elastic Protections are behavior-based endpoint rules
        # Default event_category to "process" if not detected (most common for EPP)
        if not event_category and product in ["windows", "linux", "macos", "cross_platform"]:
            event_category = "process"

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            log_sources=log_sources_list,
            data_sources=self._extract_data_sources(parsed),
            platform=platform,
            event_category=event_category,
            data_source_normalized=data_source_normalized or "defender",
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            language="eql",  # Elastic Protections uses EQL for behavior rules
            tags=parsed.tags,
            references=[],  # Elastic Protections doesn't have references
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=None,  # Not available in Elastic Protections
            rule_modified_date=None,  # Not available in Elastic Protections
        )

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Elastic Protections rule."""
        raw_sources = []
        log_source = parsed.log_source or {}

        product = (log_source.get("product") or "").lower()
        category = (log_source.get("category") or "").lower()

        # Add product-specific sources
        if product == "windows":
            raw_sources.extend(["windows_event", "endpoint"])
        elif product == "linux":
            raw_sources.extend(["linux", "endpoint"])
        elif product == "macos":
            raw_sources.extend(["macos", "endpoint"])
        elif product == "cross_platform":
            raw_sources.append("endpoint")
        else:
            raw_sources.append("endpoint")

        # Add category if present
        if category:
            raw_sources.append(category)

        # Add behavior-specific source
        raw_sources.append("behavior_event")

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Elastic Protections detection logic for display.

        Args:
            detection: Elastic EQL query string

        Returns:
            The full detection logic
        """
        if not detection:
            return "No detection logic available"

        if not isinstance(detection, str):
            return str(detection)

        return detection
