"""Elastic detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class ElasticNormalizer(BaseNormalizer):
    """Normalizer for Elastic detection rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Elastic rule to normalized format."""
        extra = parsed.extra or {}

        # Handle author which might be a list
        author = parsed.author
        if isinstance(author, list):
            author = ", ".join(author) if author else None

        # Get log sources and index patterns for taxonomy
        log_sources_list = self._normalize_log_sources(parsed.log_source)
        index_patterns = extra.get("index", [])

        # Apply taxonomy standardization
        platform, event_category, data_source_normalized = self.apply_log_source_taxonomy(
            log_sources=log_sources_list,
            index_patterns=index_patterns
        )

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
            log_sources=log_sources_list,
            data_sources=self._extract_data_sources(parsed),
            platform=platform,
            event_category=event_category,
            data_source_normalized=data_source_normalized,
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=self._format_detection_logic(parsed.detection_logic_raw),
            language=self._determine_language(parsed.detection_logic_raw, extra),
            tags=self._normalize_tags(parsed.tags),
            references=self.normalize_references(extra.get("references")),
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=self.parse_date(extra.get("creation_date")),
            rule_modified_date=self.parse_date(extra.get("updated_date")),
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
            return "ml"
        elif rule_type == "threat_match":
            return "threat_match"
        elif rule_type in ("query", "threshold", "new_terms"):
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
