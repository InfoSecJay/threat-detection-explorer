"""Microsoft Sentinel detection rule normalizer."""

from typing import Any

from app.normalizers.base import BaseNormalizer, NormalizedDetection
from app.parsers.base import ParsedRule


class SentinelNormalizer(BaseNormalizer):
    """Normalizer for Microsoft Sentinel Analytics Rules."""

    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert parsed Sentinel rule to normalized format."""
        extra = parsed.extra or {}
        log_source = parsed.log_source or {}

        # Extract log source fields
        product = log_source.get("product", "azure")
        category = log_source.get("category", "sentinel")

        # Get log sources list
        log_sources_list = self.normalize_log_sources(log_source)

        # Apply taxonomy standardization
        platform, event_category, data_source_normalized = self.apply_log_source_taxonomy(
            log_sources=log_sources_list,
            product=product,
            category=category
        )

        # Override platform based on connectors
        if not platform:
            platform = self._determine_platform(extra)

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
            log_sources=log_sources_list,
            data_sources=self._extract_data_sources(parsed),
            platform=platform or "azure",
            event_category=event_category or "siem",
            data_source_normalized=data_source_normalized or self._get_data_source_from_connectors(extra),
            mitre_tactics=parsed.mitre_attack.get("tactics", []),
            mitre_techniques=parsed.mitre_attack.get("techniques", []),
            detection_logic=parsed.detection_logic_raw,
            language="kql",
            tags=parsed.tags,
            references=[],  # Sentinel rules don't typically have references
            false_positives=self.normalize_false_positives(parsed.false_positives),
            raw_content=parsed.raw_content,
            rule_created_date=None,  # Not available in Sentinel rules
            rule_modified_date=None,  # Version available but not date
        )

    def _extract_data_sources(self, parsed: ParsedRule) -> list[str]:
        """Extract data sources from Sentinel rule connectors."""
        raw_sources = []
        extra = parsed.extra or {}
        log_source = parsed.log_source or {}

        # Add product
        product = log_source.get("product", "")
        if product:
            raw_sources.append(product)

        # Add data types from connectors
        data_types = log_source.get("data_types", [])
        for dt in data_types:
            if isinstance(dt, str):
                raw_sources.append(dt.lower())

        # Add connector-based sources
        connectors = extra.get("requiredDataConnectors", [])
        for connector in connectors:
            if isinstance(connector, dict):
                connector_id = connector.get("connectorId", "")
                if connector_id:
                    raw_sources.append(connector_id.lower())

        # Add Sentinel-specific source
        raw_sources.append("sentinel")

        # Use base normalizer's mapping
        return self.normalize_data_sources(raw_sources)

    def _determine_platform(self, extra: dict) -> str:
        """Determine platform from connector information."""
        connectors = extra.get("requiredDataConnectors", [])
        if not connectors:
            return "azure"

        connector_ids = []
        for connector in connectors:
            if isinstance(connector, dict):
                connector_id = connector.get("connectorId", "")
                if connector_id:
                    connector_ids.append(connector_id.lower())

        connector_str = " ".join(connector_ids)

        if "aws" in connector_str:
            return "aws"
        elif "gcp" in connector_str or "google" in connector_str:
            return "gcp"
        elif "office" in connector_str or "o365" in connector_str:
            return "office365"
        elif "azuread" in connector_str or "entra" in connector_str:
            return "azure_ad"
        elif "windows" in connector_str:
            return "windows"
        elif "linux" in connector_str:
            return "linux"

        return "azure"

    def _get_data_source_from_connectors(self, extra: dict) -> str:
        """Get normalized data source from connector information."""
        connectors = extra.get("requiredDataConnectors", [])
        if not connectors:
            return "sentinel"

        # Map common connectors to data sources
        connector_map = {
            "aws": "cloudtrail",
            "azuread": "azure_ad",
            "office365": "office365",
            "defender": "defender",
            "securityevents": "windows_event",
            "syslog": "syslog",
            "windowsfirewall": "windows_firewall",
            "azureactivity": "azure_activity",
        }

        for connector in connectors:
            if isinstance(connector, dict):
                connector_id = connector.get("connectorId", "").lower()
                for key, value in connector_map.items():
                    if key in connector_id:
                        return value

        return "sentinel"
