"""Elastic Hunting Queries detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_elastic_fields
from app.services.mitre import mitre_service


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
        # Normalize language name. Elastic hunting rules use language tokens
        # in their raw TOML; map them to canonical lowercase tokens.
        # `SQL` is OSQuery (Elastic's OSQuery Manager integration uses SQL
        # syntax against OSQuery virtual tables) -- canonicalize to `osquery`
        # so it filters separately from generic SQL.
        if language == "ES|QL":
            language = "esql"
        elif language == "SQL":
            language = "osquery"
        elif language.lower() in ["eql", "kql", "lucene"]:
            language = language.lower()

        # Get techniques from parsed rule
        techniques = parsed.mitre_attack.get("techniques", [])

        # Derive tactics from techniques using MITRE service
        # Elastic Hunting rules only provide techniques, so we need to look up the tactics
        tactics = parsed.mitre_attack.get("tactics", [])
        if not tactics and techniques:
            tactics = mitre_service.get_tactics_for_techniques(techniques)

        # Extract observable fields from query
        query_str = self._format_detection_logic(parsed.detection_logic_raw)
        extracted = extract_elastic_fields(query_str, language)

        # Elastic Hunting TOML doesn't embed date fields — fall back to git log
        rule_created, rule_modified = self._resolve_rule_dates(parsed.file_path)

        # Canonical taxonomy (Issue 2)
        (
            tax_platforms,
            tax_data_sources,
            tax_event_types,
            tax_matched,
            tax_fingerprint,
        ) = self._resolve_taxonomy(parsed)

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
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            detection_logic=query_str,
            language=language,
            tags=parsed.tags,
            references=extra.get("references", []),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            extracted_fields_used=extracted.fields_used,
            extracted_event_ids=extracted.event_ids,
            extracted_process_names=extracted.process_names,
            extracted_file_paths=extracted.file_paths,
            extracted_registry_keys=extracted.registry_keys,
            extracted_network_indicators=extracted.network_indicators,
            extracted_source_tables=extracted.source_tables,
            extracted_observables=[{"field": o.field, "values": o.values, "type": o.type, "subtype": o.subtype, "negated": o.negated} for o in extracted.observables],
            query_complexity=extracted.query_complexity,
            extracted_api_actions=extracted.api_actions,
            extracted_target_resources=extracted.target_resources,
            rule_created_date=rule_created,
            rule_modified_date=rule_modified,
            taxonomy_platforms=tax_platforms,
            taxonomy_data_sources=tax_data_sources,
            taxonomy_event_types=tax_event_types,
            taxonomy_matched=tax_matched,
            taxonomy_fingerprint=tax_fingerprint,
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
