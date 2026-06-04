"""Auth0 customer-detections rule normalizer.

Converts ParsedRule output from `Auth0Parser` into the canonical
`NormalizedDetection`. Always Auth0 platform; canonical data source
is `auth0_logs`. Language is `sigma` (Auth0 ships rules in Sigma
format with an accompanying Splunk implementation; we treat the
Sigma detection block as primary).
"""

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_sigma_fields


class Auth0Normalizer(BaseNormalizer):
    """Normalizer for Auth0 customer-detections."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}

        # Embedded date/modified are present in every YAML.
        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=self.parse_date(extra.get("date")),
            embedded_modified=self.parse_date(extra.get("modified")),
        )

        # Canonical taxonomy via the resolver (always
        # auth0 / auth0_logs / authentication via mappings/auth0.yaml
        # always_includes).
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        # Sigma extractor handles the detection block shape natively
        # (Auth0 uses standard Sigma `selection` / `filter` /
        # `condition`). Pull observables (event types, fields) for
        # search + UI badges.
        extracted = extract_sigma_fields(
            parsed.detection_logic_raw if isinstance(parsed.detection_logic_raw, dict) else {},
            logsource=parsed.log_source,
        )

        # Render the detection block as YAML for the rule detail view.
        import yaml
        try:
            detection_logic = yaml.dump(
                parsed.detection_logic_raw, default_flow_style=False, sort_keys=False
            ) if isinstance(parsed.detection_logic_raw, dict) else str(parsed.detection_logic_raw)
        except Exception:
            detection_logic = str(parsed.detection_logic_raw)

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="main"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author or "Okta",
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=detection_logic,
            language="sigma",
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
