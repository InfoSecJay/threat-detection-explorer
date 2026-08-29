"""Panther Labs `panther-analysis` rule normalizer.

Takes a `ParsedRule` from `PantherParser` and produces the canonical
`NormalizedDetection`. Detection logic is the Python function body
verbatim (or YAML `Detection:` block for correlation/declarative
rules that have no `.py` sibling); language tag reflects which.

Field extraction runs through `extract_panther_fields` (issue #6): an
ast walk over the Python module collecting `event.get()` /
`deep_get()` / subscript field paths and the literal comparison terms
around them. YAML `LogTypes` land in `extracted_source_tables`.
Correlation/declarative rules (serialized YAML, not Python) fail
`ast.parse` and degrade to LogTypes-only extraction.
"""

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_panther_fields


class PantherNormalizer(BaseNormalizer):
    """Normalizer for Panther Labs panther-analysis rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        extra = parsed.extra or {}

        # Panther YAMLs don't embed a canonical date field. Fall
        # back to git log via BaseNormalizer._resolve_rule_dates so
        # rules still get created/modified timestamps.
        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=None,
            embedded_modified=None,
        )

        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        language = extra.get("language") or "python"
        # Detection logic: either the .py source (most rules), the
        # YAML Detection block serialized (correlation + declarative),
        # or an empty string as a last resort.
        detection_logic = parsed.detection_logic_raw
        if not isinstance(detection_logic, str):
            detection_logic = str(detection_logic) if detection_logic else ""

        # AST field extraction (issue #6) — see module docstring.
        extracted = extract_panther_fields(
            detection_logic if language == "python" else "",
            log_types=extra.get("log_types") or [],
        )

        # References list from YAML `Reference:` field, plus we surface
        # `Runbook` text as a false-positive-style triage note (Panther's
        # Runbook field == our false_positives semantic: "how an analyst
        # investigates + when to dismiss").
        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="develop"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,  # None — Panther rules don't carry an Author field
            status=self.normalize_status(parsed.status),
            # Signal-only (`CreateAlert: false` / `panther-signal`) is a
            # building block, not a maturity level (issue #26).
            is_building_block=bool(extra.get("is_signal_only")),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            mitre_groups=parsed.mitre_attack.get("groups", []),
            mitre_software=parsed.mitre_attack.get("software", []),
            detection_logic=detection_logic,
            language=language,
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
