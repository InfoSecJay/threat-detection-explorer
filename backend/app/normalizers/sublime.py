"""Sublime Security detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_sublime_fields


class SublimeNormalizer(BaseNormalizer):
    """Normalizer for Sublime Security detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Sublime rule to normalized format."""
        extra = parsed.extra or {}

        # Extract observable fields from MQL query
        query_str = self._format_detection_logic(parsed.detection_logic_raw)
        extracted = extract_sublime_fields(query_str)

        # Sublime YAML doesn't embed date fields — fall back to git log
        rule_created, rule_modified = self._resolve_rule_dates(parsed.file_path)

        # Canonical taxonomy
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

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
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=query_str,
            language="mql",  # Sublime uses Message Query Language (MQL)
            tags=parsed.tags,
            references=self.normalize_references(extra.get("references")),
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
            platforms=platforms,
            data_sources=data_sources,
            event_types=event_types,
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
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
        """Format Sublime detection logic (source field) for display."""
        if not detection:
            return "No detection logic available"

        if not isinstance(detection, str):
            return str(detection)

        return detection
