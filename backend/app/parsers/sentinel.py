"""Microsoft Sentinel detection rule parser."""

import logging
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


class SentinelParser(BaseParser):
    """Parser for Microsoft Sentinel Analytics Rules (YAML format)."""

    # Mapping of MITRE ATT&CK tactic names to IDs
    # Sentinel uses CamelCase or space-separated names
    TACTIC_MAPPING = {
        # CamelCase format (Sentinel style)
        "reconnaissance": "TA0043",
        "resourcedevelopment": "TA0042",
        "initialaccess": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilegeescalation": "TA0004",
        "defenseevasion": "TA0005",
        "credentialaccess": "TA0006",
        "discovery": "TA0007",
        "lateralmovement": "TA0008",
        "collection": "TA0009",
        "commandandcontrol": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
        # Space-separated format
        "resource development": "TA0042",
        "initial access": "TA0001",
        "privilege escalation": "TA0004",
        "defense evasion": "TA0005",
        "credential access": "TA0006",
        "lateral movement": "TA0008",
        "command and control": "TA0011",
    }

    @property
    def source_name(self) -> str:
        return "sentinel"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Sentinel Analytics rule file."""
        path_str = str(file_path).lower()

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Must be in Solutions directory with Analytic Rules
        if "solutions" not in path_str:
            return False

        # Should be in Analytic Rules folder
        if "analytic" not in path_str:
            return False

        # Exclude test and deprecated directories
        excluded = ["tests", "deprecated", "test", ".git", "sample"]
        return not any(ex in path_str.lower() for ex in excluded)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Microsoft Sentinel Analytics YAML rule file."""
        try:
            data = yaml.safe_load(content)

            if not isinstance(data, dict):
                return None

            # Required field: name
            name = data.get("name")
            if not name:
                logger.debug(f"Skipping {file_path}: no name")
                return None

            # Required field: query (detection logic)
            query = data.get("query")
            if not query:
                logger.debug(f"Skipping {file_path}: no query")
                return None

            # Must be a Scheduled rule (not hunting query)
            kind = data.get("kind", "")
            if kind and kind.lower() not in ["scheduled", "nrt"]:
                logger.debug(f"Skipping {file_path}: not a scheduled rule (kind={kind})")
                return None

            # Extract MITRE ATT&CK
            mitre_attack = self._extract_mitre(data)

            # Extract log source from requiredDataConnectors
            log_source = self._extract_log_source(data)

            # Extract tags
            tags = data.get("tags", []) or []
            if isinstance(tags, str):
                tags = [tags]

            # Extract severity
            severity = data.get("severity", "unknown")

            # Extract status
            status = data.get("status", "unknown")

            # Description handling
            description = data.get("description", "")
            if isinstance(description, str):
                description = description.strip()

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=name,
                description=description,
                author="Microsoft",
                status=status,
                severity=severity,
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=query,
                false_positives=[],
                extra={
                    "id": data.get("id"),
                    "kind": kind,
                    "version": data.get("version"),
                    "queryFrequency": data.get("queryFrequency"),
                    "queryPeriod": data.get("queryPeriod"),
                    "triggerOperator": data.get("triggerOperator"),
                    "triggerThreshold": data.get("triggerThreshold"),
                    "requiredDataConnectors": data.get("requiredDataConnectors", []),
                    "entityMappings": data.get("entityMappings", []),
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_mitre(self, data: dict) -> dict:
        """Extract MITRE ATT&CK tactics and techniques from Sentinel rule.

        Sentinel uses:
        - tactics: List of tactic names like ["Impact", "DefenseEvasion"]
        - relevantTechniques: List of technique IDs like ["T1565.001", "T1562.008"]
        """
        tactics = []
        techniques = []

        # Extract tactics
        raw_tactics = data.get("tactics", [])
        if isinstance(raw_tactics, str):
            raw_tactics = [raw_tactics]

        for tactic in raw_tactics:
            if not isinstance(tactic, str):
                continue
            # Normalize tactic name (remove spaces, lowercase)
            normalized = tactic.lower().replace(" ", "").replace("-", "").replace("_", "")
            if normalized in self.TACTIC_MAPPING:
                tactic_id = self.TACTIC_MAPPING[normalized]
                if tactic_id not in tactics:
                    tactics.append(tactic_id)

        # Extract techniques
        raw_techniques = data.get("relevantTechniques", [])
        if isinstance(raw_techniques, str):
            raw_techniques = [raw_techniques]

        for technique in raw_techniques:
            if not isinstance(technique, str):
                continue
            # Normalize technique ID (ensure uppercase, T prefix)
            tech_id = technique.upper()
            if not tech_id.startswith("T"):
                tech_id = "T" + tech_id
            if tech_id not in techniques:
                techniques.append(tech_id)

        return {"tactics": tactics, "techniques": techniques}

    def _extract_log_source(self, data: dict) -> dict:
        """Extract log source information from requiredDataConnectors."""
        log_source = {
            "product": "azure",
            "category": "sentinel",
        }

        connectors = data.get("requiredDataConnectors", [])
        if not connectors:
            return log_source

        # Extract data types from connectors
        data_types = []
        connector_ids = []

        for connector in connectors:
            if isinstance(connector, dict):
                connector_id = connector.get("connectorId", "")
                if connector_id:
                    connector_ids.append(connector_id)

                types = connector.get("dataTypes", [])
                if isinstance(types, list):
                    data_types.extend(types)

        # Determine product from connector IDs
        connector_str = " ".join(connector_ids).lower()
        if "aws" in connector_str:
            log_source["product"] = "aws"
        elif "gcp" in connector_str or "google" in connector_str:
            log_source["product"] = "gcp"
        elif "office" in connector_str or "o365" in connector_str:
            log_source["product"] = "office365"
        elif "azuread" in connector_str or "entra" in connector_str:
            log_source["product"] = "azure_ad"
        elif "defender" in connector_str:
            log_source["product"] = "defender"

        if data_types:
            log_source["data_types"] = data_types

        return log_source
