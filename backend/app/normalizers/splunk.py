"""Splunk Security Content detection rule normalizer."""

from typing import Any

from app.services.taxonomy.canonical import VENDOR_RULE_TYPE_MODALITY
from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule
from app.services.field_extractor import extract_splunk_fields


class SplunkNormalizer(BaseNormalizer):
    """Normalizer for Splunk Security Content detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Splunk rule to normalized format."""
        extra = parsed.extra or {}

        # Extract observable fields from SPL search
        search_str = self._format_detection_logic(parsed.detection_logic_raw)
        extracted = extract_splunk_fields(search_str)

        # Splunk's date fields vary by schema:
        #   old schema: `date` (created only)
        #   new schema: `creation_date` + `modification_date`
        # The parser normalizes `date` to be either the old-schema
        # value OR the new-schema `creation_date`. New schema also
        # gives us `modification_date` explicitly; fall back to git
        # log for old-schema rules that don't embed it.
        rule_created, rule_modified = self._resolve_rule_dates(
            parsed.file_path,
            embedded_created=self.parse_date(extra.get("date")),
            embedded_modified=self.parse_date(extra.get("modification_date")),
        )

        # Canonical taxonomy
        platforms, data_sources, event_types, matched, fingerprint = self._resolve_taxonomy(parsed)

        # Analytic story values (vendor-preserved) -> use_cases. The
        # parser stashes the raw upstream values; we dedupe + drop empties
        # but keep the vendor's casing.
        use_cases: list[str] = []
        for story in extra.get("analytic_stories", []) or []:
            if isinstance(story, str):
                s = story.strip()
                if s and s not in use_cases:
                    use_cases.append(s)

        return NormalizedDetection(
            id=self.generate_id(parsed.source, parsed.file_path),
            source=parsed.source,
            source_file=parsed.file_path,
            source_repo_url=self.repo_url,
            source_rule_url=self.build_source_rule_url(parsed.file_path, branch="develop"),
            rule_id=extra.get("id"),
            title=parsed.title,
            description=parsed.description,
            author=parsed.author,
            status=self.normalize_status(parsed.status),
            severity=self.normalize_severity(parsed.severity),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=search_str,
            language="spl",
            # ESCU `type`: TTP / Anomaly / Hunting / Correlation / Baseline (#105)
            rule_modality=VENDOR_RULE_TYPE_MODALITY.get(str(extra.get("type") or "").lower(), "rule"),
            tags=self._normalize_tags(parsed.tags),
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
            use_cases=use_cases,
            taxonomy_matched=matched,
            taxonomy_fingerprint=fingerprint,
        )

    def _normalize_log_sources(self, log_source: dict) -> list[str]:
        """Extract normalized log sources from Splunk metadata."""
        sources = []

        product = log_source.get("product")
        if product:
            sources.append(product.lower())

        # Get from data sources
        data_sources = log_source.get("data_sources", [])
        for ds in data_sources:
            if ds:
                sources.append(ds.lower())

        return list(set(sources))

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Splunk rule."""
        raw_sources = []

        # Get explicit data sources from Splunk metadata
        data_sources = parsed.extra.get("data_source", [])
        for ds in data_sources:
            if ds:
                raw_sources.append(ds)

        # Infer from search query
        search = parsed.detection_logic_raw.get("search", "")
        if search:
            search_lower = search.lower()
            if "sysmon" in search_lower:
                raw_sources.append("sysmon")
            if "wineventlog" in search_lower:
                raw_sources.append("windows_event")
            if "security" in search_lower and "windows" in search_lower:
                raw_sources.append("security_event")
            if "powershell" in search_lower:
                raw_sources.append("powershell")
            if "registry" in search_lower:
                raw_sources.append("registry")
            if "process" in search_lower:
                raw_sources.append("process_creation")
            if "network" in search_lower:
                raw_sources.append("network")
            if "dns" in search_lower:
                raw_sources.append("dns")
            if "authentication" in search_lower or "logon" in search_lower:
                raw_sources.append("authentication")
            if "cloudtrail" in search_lower or "aws" in search_lower:
                raw_sources.append("aws")
            if "azure" in search_lower:
                raw_sources.append("azure")
            if "gcp" in search_lower or "google" in search_lower:
                raw_sources.append("gcp")

        # Use the base normalizer's mapping for consistent output
        return self.normalize_data_sources(raw_sources)

    def _format_detection_logic(self, detection: Any) -> str:
        """Format Splunk SPL search for display.

        Args:
            detection: Detection logic dict with search

        Returns:
            The full search query
        """
        if not isinstance(detection, dict):
            return str(detection)

        search = detection.get("search", "")
        if not search:
            return "No search query defined"

        return search

    def _normalize_tags(self, tags: list) -> list[str]:
        """Normalize Splunk tags to a consistent format.

        Splunk's parser emits tags like ``story:scattered_lapsus$_hunters``
        (analytic_story name), ``asset:endpoint``, ``domain:identity``.
        The ``story:`` prefix is high-signal — it's how the Threat Pulse
        feature distinguishes campaign/actor names from the small finite
        set of asset/domain values. Preserve it; drop the others (asset
        and domain duplicate information already in the canonical
        ``taxonomy_platforms`` / ``taxonomy_event_types`` columns and
        only add noise to the tag list).
        """
        normalized = []
        for tag in tags:
            if not (tag and isinstance(tag, str)):
                continue
            if tag.startswith("story:"):
                # Keep the prefix verbatim — downstream extraction
                # (api/routes/trending.py) keys off it.
                _, value = tag.split(":", 1)
                normalized.append(f"story:{value.lower().replace(' ', '_')}")
            elif tag.startswith(("asset:", "domain:")):
                # Drop entirely — captured by canonical taxonomy columns.
                continue
            else:
                normalized.append(tag.lower().replace(" ", "_"))
        return normalized
