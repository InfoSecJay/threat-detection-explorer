"""Elastic detection rule normalizer."""

from typing import Any, Optional

from app.services.taxonomy.canonical import VENDOR_RULE_TYPE_MODALITY
from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_elastic_fields


def _extract_elastic_use_cases(raw_tags: list) -> list[str]:
    """Pull vendor-preserved `Use Case:` display values out of a
    raw Elastic tag list.

    Elastic authors add tags like `Use Case: Threat Detection`,
    `Use Case: Vulnerability`, `Use Case: Guided Onboarding`. This
    helper strips the `Use Case:` prefix, trims whitespace, keeps the
    original casing, and dedupes.
    """
    out: list[str] = []
    for tag in raw_tags or []:
        if not isinstance(tag, str):
            continue
        lower = tag.strip().lower()
        if not lower.startswith("use case:"):
            continue
        value = tag.split(":", 1)[1].strip()
        if value and value not in out:
            out.append(value)
    return out


class ElasticNormalizer(BaseNormalizer):
    """Normalizer for Elastic detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Elastic rule to normalized format."""
        extra = parsed.extra or {}

        # Handle author which might be a list
        author = parsed.author
        if isinstance(author, list):
            author = ", ".join(author) if author else None

        # Building-block detection: either the TOML carries the field, OR
        # the file lives under `rules_building_block/`. Both are signals
        # that this rule produces sub-detection signal rather than firing
        # alerts directly. We surface this with a `building_block` tag so
        # users can filter in/out of the catalog. Also injects the
        # original ``building_block_type`` value (e.g. "default") so the
        # tag carries the vendor's chosen sub-category.
        is_building_block = bool(extra.get("building_block_type")) or (
            "rules_building_block" in parsed.file_path
        )

        # Extract observable fields from detection query
        query_str = self._format_detection_logic(parsed.detection_logic_raw)
        lang = self._determine_language(parsed.detection_logic_raw, extra)
        # Rule index patterns + integrations tell the extractor which
        # stream `event.action` belongs to (endpoint verb vs API action).
        extracted = extract_elastic_fields(
            query_str, lang,
            indices=extra.get("index") or [],
            integrations=extra.get("integration") or [],
        )

        # Prefer embedded Elastic dates; fall back to git log when a rule omits them
        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=self.parse_date(extra.get("creation_date")),
            embedded_modified=self.parse_date(extra.get("updated_date")),
        )

        # Canonical taxonomy
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        # Extract vendor `Use Case:` prefixed tags -> use_cases with
        # vendor-preserved casing (before the tag-normalization
        # pipeline lowercases them).
        use_cases = _extract_elastic_use_cases(parsed.tags)

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path),
            rule_id=extra.get("rule_id"),
            title=parsed.title,
            description=parsed.description,
            author=author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=query_str,
            language=lang,
            tags=self._build_tags(parsed.tags, is_building_block, extra.get("building_block_type")),
            is_building_block=is_building_block,
            # Vendor rule type -> modality (#105). Building blocks are lifted
            # in __post_init__ when the type gives nothing more specific.
            rule_modality=VENDOR_RULE_TYPE_MODALITY.get(str(extra.get("type") or "").lower(), "rule"),
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            investigation_guide=_guide_text(parsed.extra.get("note"), parsed.extra.get("setup")),
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
            use_cases=use_cases,
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
        )

    def _normalize_log_sources(self, log_source: dict) -> list[str]:
        """Extract normalized log sources from Elastic index patterns."""
        sources = []

        product = log_source.get("product")
        if product:
            sources.append(product.lower())

        # Extract meaningful names from index patterns
        indices = log_source.get("indices", [])
        for index in indices:
            index_lower = index.lower()

            # Extract product hints from index patterns
            if "winlogbeat" in index_lower:
                sources.append("windows")
            elif "auditbeat" in index_lower:
                sources.append("auditbeat")
            elif "filebeat" in index_lower:
                sources.append("filebeat")
            elif "packetbeat" in index_lower:
                sources.append("network")
            elif "logs-endpoint" in index_lower:
                sources.append("endpoint")

        return list(set(sources))

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Elastic rule metadata."""
        raw_sources = []

        # Get index patterns and extract hints
        indices = parsed.extra.get("index", [])
        for index in indices:
            index_lower = index.lower()

            # Extract specific data source hints from index patterns
            if "sysmon" in index_lower:
                raw_sources.append("sysmon")
            if "security" in index_lower:
                raw_sources.append("security_event")
            if "powershell" in index_lower:
                raw_sources.append("powershell")
            if "endpoint" in index_lower:
                raw_sources.append("endpoint")
            if "winlogbeat" in index_lower:
                raw_sources.append("windows_event")
            if "auditbeat" in index_lower:
                raw_sources.append("auditd")
            if "filebeat" in index_lower:
                raw_sources.append("file_monitoring")
            if "packetbeat" in index_lower:
                raw_sources.append("network")
            if "aws" in index_lower or "cloudtrail" in index_lower:
                raw_sources.append("aws")
            if "azure" in index_lower:
                raw_sources.append("azure")
            if "gcp" in index_lower:
                raw_sources.append("gcp")
            if "o365" in index_lower or "office365" in index_lower:
                raw_sources.append("o365")
            if "okta" in index_lower:
                raw_sources.append("okta")
            if "github" in index_lower:
                raw_sources.append("github")

        # Also check log source product
        product = parsed.log_source.get("product", "")
        if product:
            raw_sources.append(product)

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Elastic detection logic (query) for display.

        Args:
            detection: Detection logic dict with type and query

        Returns:
            The full query string
        """
        if not isinstance(detection, dict):
            return str(detection)

        query = detection.get("query", "")
        if query:
            return query

        # For ML rules, return a description
        if detection.get("type") == "machine_learning":
            job_id = detection.get("machine_learning_job_id", "unknown")
            return f"Machine Learning Job: {job_id}"

        return str(detection)

    def _normalize_tags(self, tags: list) -> list[str]:
        """Normalize Elastic tags to consistent format."""
        normalized = []
        for tag in tags:
            if tag:
                # Convert to lowercase and replace spaces
                normalized.append(tag.lower().replace(" ", "_"))
        return normalized

    def _build_tags(
        self,
        raw_tags: list,
        is_building_block: bool,
        building_block_type: Optional[str] = None,
    ) -> list[str]:
        """Normalize tags + inject ``building_block`` markers when applicable.

        Building-block rules get two tags: a flat ``building_block``
        flag for cheap filtering, and ``building_block_type:<value>``
        when the TOML specified a subtype (e.g. "default"). Both are
        appended after normalization so they don't collide with the
        lowercase + underscore transform.
        """
        normalized = self._normalize_tags(raw_tags)
        if is_building_block:
            if "building_block" not in normalized:
                normalized.append("building_block")
            if building_block_type:
                subtype_tag = f"building_block_type:{building_block_type.lower()}"
                if subtype_tag not in normalized:
                    normalized.append(subtype_tag)
        return normalized

    def _determine_language(self, detection: Any, extra: dict) -> str:
        """Determine the query language used by the Elastic rule.

        Elastic rules can use various query languages:
        - eql: Event Query Language
        - esql: Elasticsearch Query Language (ES|QL)
        - kql: Kibana Query Language (for query type with language: kuery)
        - lucene: Lucene query syntax (for query type with language: lucene)
        - ml: Machine Learning rules
        - threshold: Threshold-based rules (uses KQL/Lucene)
        - new_terms: New terms rules (uses KQL/Lucene)
        - threat_match: Indicator match rules
        """
        if not isinstance(detection, dict):
            return "unknown"

        rule_type = detection.get("type", "").lower()

        # Direct language mappings for rule types
        if rule_type == "eql":
            return "eql"
        elif rule_type == "esql":
            return "esql"
        elif rule_type == "machine_learning":
            # No query at all -- the ML job is the detection. The
            # modality says so; language must not (#105 / B7).
            return "none"
        elif rule_type in ("query", "threshold", "new_terms", "threat_match"):
            # threat_match joins a KQL/Lucene query against indicator
            # indices: the language is the query's, the modality is
            # indicator_match.
            # These use a language field to specify KQL vs Lucene
            lang = detection.get("language") or extra.get("language", "")
            if lang:
                lang_lower = lang.lower()
                if lang_lower == "kuery":
                    return "kql"
                elif lang_lower == "lucene":
                    return "lucene"
                elif lang_lower == "eql":
                    return "eql"
                elif lang_lower == "esql":
                    return "esql"
            # Default for query type without language specified
            return "kql"

        return "unknown"


def _guide_text(note, setup) -> "str | None":
    """Elastic `note` is the investigation guide; `setup` (when
    present) is appended under its own heading so the page shows one
    document."""
    parts = []
    if isinstance(note, str) and note.strip():
        parts.append(note.strip())
    if isinstance(setup, str) and setup.strip():
        parts.append("## Setup\n\n" + setup.strip())
    return "\n\n".join(parts) or None
