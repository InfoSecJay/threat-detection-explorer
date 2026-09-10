"""Microsoft Sentinel detection rule normalizer."""

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_sentinel_fields
from app.services.threat_tags import threat_reference_tags


class SentinelNormalizer(BaseNormalizer):
    """Normalizer for Microsoft Sentinel Analytics Rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Sentinel rule to normalized format."""
        extra = parsed.extra or {}

        # Extract observable fields from KQL query
        query_str = parsed.detection_logic_raw if isinstance(parsed.detection_logic_raw, str) else str(parsed.detection_logic_raw)
        extracted = extract_sentinel_fields(query_str)

        # Sentinel analytic rules don't embed date fields — fall back to git log
        rule_created, rule_modified = self._resolve_rule_dates(parsed.file_path)

        # Canonical taxonomy
        taxonomy = self._resolve_taxonomy_full(parsed)

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="master"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author or "Microsoft",
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=query_str,
            language="kql",
            tags=parsed.tags,
            # Tags naming a threat actor/software (NOBELIUM, Solorigate,
            # DEV-0537) become story labels — the dedicated tier resolves
            # them to actors at query time (issues #20/#34). Ingestion
            # pre-loads the alias registries for this source.
            use_cases=threat_reference_tags(parsed.tags),
            references=[],
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
            platforms=taxonomy["platforms"],
            data_sources=taxonomy["data_sources"],
            event_types=taxonomy["event_types"],
            # Solution metadata hints (#138): providers as products, the
            # content-hub domain as the fallback domain.
            products=taxonomy.get("products") or [],
            domains=taxonomy.get("domains") or [],
            taxonomy_matched=taxonomy["matched"],
            taxonomy_fingerprint=taxonomy["fingerprint"],
        )
