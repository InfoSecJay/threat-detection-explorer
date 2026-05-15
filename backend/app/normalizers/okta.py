"""Okta customer-detections rule normalizer.

Converts ParsedRule output from `OktaParser` into the canonical
`NormalizedDetection`. Always Okta platform; canonical data source
is `okta_system_log`. Severity defaulted to `medium` because the
upstream YAML never carries severity.
"""

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class OktaNormalizer(BaseNormalizer):
    """Normalizer for Okta customer-detections."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}

        # Embedded created/modified dates are present in every YAML.
        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=self.parse_date(extra.get("created_date")),
            embedded_modified=self.parse_date(extra.get("modified_date")),
        )

        # Canonical taxonomy via the resolver (always okta / okta_system_log /
        # authentication via mappings/okta.yaml always_includes).
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        # Primary language is `oie` / `spl` / `datadog` per the parser's
        # priority order; pass through verbatim.
        primary_language = extra.get("primary_language") or "oie"

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="master"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author or "Okta",
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=parsed.detection_logic_raw or "",
            language=primary_language,
            tags=parsed.tags,
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            # Field extraction TODO for OIE / Okta SPL -- the OIE syntax
            # (e.g. `eventType eq "user.session.access_admin_app"`) is
            # similar enough to KQL that a small extractor could be
            # added. Skipping for now to keep the integration tight.
            extracted_fields_used=[],
            extracted_event_ids=[],
            extracted_process_names=[],
            extracted_file_paths=[],
            extracted_registry_keys=[],
            extracted_network_indicators=[],
            extracted_source_tables=[],
            extracted_observables=[],
            query_complexity="simple",
            extracted_api_actions=[],
            extracted_target_resources=[],
            rule_created_date=rule_created,
            rule_modified_date=rule_modified,
            platforms=platforms,
            data_sources=data_sources,
            event_types=event_types,
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
        )
