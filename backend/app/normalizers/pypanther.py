"""Panther Labs `pypanther` rule normalizer (issue #27).

Mirror of PantherNormalizer for the Pythonic framework: metadata came
from class attributes (extracted by PyPantherParser via ast), the
detection logic is the whole module source verbatim, and field
extraction runs through the same `extract_panther_fields` ast walk —
the event-access idioms are identical between panther-analysis and
pypanther.

The parser resolved `LogType.*` enum members to their string values
("AWS.CloudTrail"), so taxonomy resolution reuses the panther-analysis
mapping unchanged (`taxonomy.vendors.panther.resolve`).
"""

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_panther_fields


class PyPantherNormalizer(BaseNormalizer):
    """Normalizer for Panther Labs pypanther framework rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}

        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=None,
            embedded_modified=None,
        )

        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        detection_logic = parsed.detection_logic_raw
        if not isinstance(detection_logic, str):
            detection_logic = str(detection_logic) if detection_logic else ""

        extracted = extract_panther_fields(
            detection_logic,
            log_types=extra.get("log_types") or [],
        )

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="main"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=None,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            mitre_groups=parsed.mitre_attack.get("groups", []),
            mitre_software=parsed.mitre_attack.get("software", []),
            detection_logic=detection_logic,
            language=extra.get("language") or "python",
            tags=parsed.tags,
            references=self.normalize_references(extra.get("reference")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            extracted_fields_used=extracted.fields_used,
            extracted_event_ids=extracted.event_ids,
            extracted_process_names=extracted.process_names,
            extracted_file_paths=extracted.file_paths,
            extracted_registry_keys=extracted.registry_keys,
            extracted_network_indicators=extracted.network_indicators,
            extracted_source_tables=extracted.source_tables,
            extracted_observables=[
                {
                    "field": o.field,
                    "values": o.values,
                    "type": o.type,
                    "subtype": o.subtype,
                    "negated": o.negated,
                }
                for o in extracted.observables
            ],
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
