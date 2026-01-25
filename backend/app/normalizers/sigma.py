"""Sigma detection rule normalizer."""

import yaml
from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class SigmaNormalizer(BaseNormalizer):
    """Normalizer for Sigma detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Sigma rule to normalized format."""
        extra = parsed.extra or {}
        log_source = parsed.log_source or {}

        # Extract Sigma-specific log source fields
        product = log_source.get("product", "")
        category = log_source.get("category", "")
        service = log_source.get("service", "")

        # Get the raw log sources list
        log_sources_list = self.normalize_log_sources(log_source)

        # Apply taxonomy standardization
        platform, event_category, data_source_normalized = self.apply_log_source_taxonomy(
            log_sources=log_sources_list,
            product=product,
            category=category,
            service=service
        )

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="master"),
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
            data_source_normalized=data_source_normalized,
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            language="sigma",
            tags=parsed.tags,
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=self.parse_date(extra.get("date")),
            rule_modified_date=self.parse_date(extra.get("modified")),
        )

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Sigma log source."""
        raw_sources = []
        log_source = parsed.log_source or {}

        product = (log_source.get("product") or "").lower()
        category = (log_source.get("category") or "").lower()
        service = (log_source.get("service") or "").lower()

        # Add service as primary data source indicator
        if service:
            raw_sources.append(service)

        # Add category which often indicates the event type
        if category:
            raw_sources.append(category)

        # Add product-specific defaults if no service specified
        if product and not service:
            if product == "windows":
                raw_sources.append("windows_event")
            elif product == "linux":
                raw_sources.append("linux")
            elif product == "macos":
                raw_sources.append("macos")

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Sigma detection logic as YAML for display.

        Args:
            detection: Sigma detection dict

        Returns:
            YAML-formatted detection logic
        """
        if not isinstance(detection, dict):
            return str(detection)

        try:
            # Format as YAML for readability (matching the original rule format)
            return yaml.dump(detection, default_flow_style=False, sort_keys=False, allow_unicode=True)
        except Exception:
            return str(detection)
