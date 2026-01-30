"""Elastic Hunting Queries detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class ElasticHuntingNormalizer(BaseNormalizer):
    """Normalizer for Elastic Hunting Queries detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Elastic Hunting rule to normalized format."""
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

        # Map product to platform if not already set
        if not platform:
            product_platform_map = {
                "windows": "windows",
                "linux": "linux",
                "macos": "macos",
                "aws": "aws",
                "azure": "azure",
                "okta": "okta",
                "llm": "llm",
                "cross_platform": "cross_platform",
            }
            platform = product_platform_map.get(product, "")

        # Get language from extra (default to ES|QL)
        language_list = extra.get("language", ["ES|QL"])
        language = language_list[0] if language_list else "ES|QL"
        # Normalize language name
        if language == "ES|QL":
            language = "esql"
        elif language.lower() in ["eql", "kql", "lucene"]:
            language = language.lower()

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path),
            rule_id=extra.get("uuid"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            log_sources=log_sources_list,
            data_sources=self._extract_data_sources(parsed),
            platform=platform,
            event_category=event_category or "hunting",
            data_source_normalized=data_source_normalized or self._get_data_source_from_integration(extra),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            language=language,
            tags=parsed.tags,
            references=[],  # Hunting queries don't have references field
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=None,  # Not available in Elastic Hunting
            rule_modified_date=None,  # Not available in Elastic Hunting
        )

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Elastic Hunting rule."""
        raw_sources = []
        log_source = parsed.log_source or {}
        extra = parsed.extra or {}

        product = (log_source.get("product") or "").lower()

        # Add product-specific sources
        if product == "windows":
            raw_sources.extend(["windows_event", "endpoint"])
        elif product == "linux":
            raw_sources.extend(["linux", "endpoint"])
        elif product == "macos":
            raw_sources.extend(["macos", "endpoint"])
        elif product == "aws":
            raw_sources.extend(["aws", "cloud"])
        elif product == "azure":
            raw_sources.extend(["azure", "cloud"])
        elif product == "okta":
            raw_sources.extend(["okta", "identity"])
        elif product == "llm":
            raw_sources.extend(["llm", "application"])
        elif product == "cross_platform":
            raw_sources.append("endpoint")
        else:
            raw_sources.append("endpoint")

        # Add integration-specific sources
        integration = extra.get("integration", [])
        for integ in integration:
            if isinstance(integ, str):
                raw_sources.append(integ.lower())

        # Add hunting-specific source
        raw_sources.append("hunting_query")

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _get_data_source_from_integration(self, extra: dict) -> str:
        """Get normalized data source from integration field."""
        integration = extra.get("integration", [])
        if not integration:
            return "endpoint"

        # Map common integrations to data sources
        integ_map = {
            "okta": "okta",
            "aws": "cloudtrail",
            "azure": "azure",
            "windows": "windows_event",
            "linux": "linux",
            "macos": "macos",
            "endpoint": "endpoint",
        }

        for integ in integration:
            integ_lower = str(integ).lower()
            for key, value in integ_map.items():
                if key in integ_lower:
                    return value

        return "endpoint"

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Elastic Hunting detection logic for display.

        Args:
            detection: ES|QL or other query string(s)

        Returns:
            The full detection logic
        """
        if not detection:
            return "No detection logic available"

        if not isinstance(detection, str):
            return str(detection)

        return detection
