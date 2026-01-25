"""Sublime Security detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class SublimeNormalizer(BaseNormalizer):
    """Normalizer for Sublime Security detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Sublime rule to normalized format."""
        extra = parsed.extra or {}

        # Get log sources
        log_sources_list = self.normalize_log_sources(parsed.log_source)

        # Add email-related context for taxonomy
        email_context = log_sources_list + ["email", "email_security"]

        # Apply taxonomy standardization
        platform, event_category, data_source_normalized = self.apply_log_source_taxonomy(
            log_sources=email_context
        )

        # Sublime is email security - force platform to email if not detected
        if not platform:
            platform = "email"

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
            event_category=event_category or "email",
            data_source_normalized=data_source_normalized or "exchange",
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            language="mql",  # Sublime uses Message Query Language (MQL)
            tags=parsed.tags,
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=None,  # Sublime doesn't have creation dates
            rule_modified_date=None,  # Sublime doesn't have modified dates
        )

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Sublime rule."""
        raw_sources = ["email"]

        # Add detection methods as data sources
        detection_methods = parsed.extra.get("detection_methods", [])
        if detection_methods:
            for method in detection_methods:
                if isinstance(method, str):
                    raw_sources.append(method)

        # Add attack types as context
        attack_types = parsed.extra.get("attack_types", [])
        if attack_types:
            for attack_type in attack_types:
                if isinstance(attack_type, str):
                    raw_sources.append(attack_type)

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Sublime detection logic (source field) for display.

        Args:
            detection: Sublime MQL query string (from source field)

        Returns:
            The full source/detection logic
        """
        if not detection:
            return "No detection logic available"

        if not isinstance(detection, str):
            return str(detection)

        return detection
