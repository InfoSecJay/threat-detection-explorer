"""Elastic Protection Artifacts detection rule parser."""

import logging
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


class ElasticProtectionsParser(BaseParser):
    """Parser for Elastic Protection Artifacts (TOML behavior rules)."""

    @property
    def source_name(self) -> str:
        return "elastic_protections"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is an Elastic Protections rule file."""
        path_str = str(file_path).lower()

        # Must be TOML
        if not path_str.endswith(".toml"):
            return False

        # Must be in behavior/rules directory
        if "behavior" not in path_str:
            return False

        # Exclude deprecated and test directories
        excluded = ["deprecated", "tests", "test"]
        return not any(ex in path_str.lower() for ex in excluded)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse an Elastic Protections TOML rule file."""
        try:
            data = tomllib.loads(content)

            # Get the rule section
            rule = data.get("rule", {})
            if not rule:
                logger.debug(f"Skipping {file_path}: no rule section")
                return None

            # Required field: name
            name = rule.get("name")
            if not name:
                logger.debug(f"Skipping {file_path}: no name")
                return None

            # Get query (detection logic)
            query = rule.get("query", "")

            # Extract MITRE info from threat section
            mitre_attack = self._extract_mitre(data)

            # Determine OS from file path or os_list
            os_list = rule.get("os_list", [])
            log_source = self._determine_log_source(file_path, os_list)

            # Extract severity from actions or default to medium
            severity = self._determine_severity(data)

            # Build tags
            tags = ["behavior_rule", "endpoint_protection"]
            if os_list:
                for os_name in os_list:
                    if isinstance(os_name, str):
                        tags.append(os_name.lower())

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=name,
                description=rule.get("description"),
                author="Elastic",  # All rules authored by Elastic
                status="stable",  # Production rules
                severity=severity,
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=query,
                false_positives=[],  # Elastic Protections doesn't have false positives field
                extra={
                    "id": rule.get("id"),
                    "version": rule.get("version"),
                    "license": rule.get("license"),
                    "min_endpoint_version": rule.get("min_endpoint_version"),
                    "actions": data.get("actions", []),
                },
            )

        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_mitre(self, data: dict) -> dict:
        """Extract MITRE ATT&CK tactics and techniques from threat section.

        The TOML structure uses [[threat]] for array of threat items, and
        [[threat.technique]] creates nested arrays within each threat item.
        Example structure after parsing:
        threat = [
            {
                "tactic": {"id": "TA0007", "name": "Discovery"},
                "technique": [
                    {"id": "T1069", "name": "...", "subtechnique": [{"id": "T1069.002"}]},
                    {"id": "T1087", "name": "...", "subtechnique": [{"id": "T1087.002"}]},
                ]
            }
        ]
        """
        tactics = []
        techniques = []

        threat = data.get("threat", [])
        if not threat:
            return {"tactics": tactics, "techniques": techniques}

        # Ensure threat is a list
        threat_list = threat if isinstance(threat, list) else [threat]

        for threat_item in threat_list:
            if not isinstance(threat_item, dict):
                continue

            # Extract tactic (single dict per threat item)
            tactic = threat_item.get("tactic", {})
            if isinstance(tactic, dict):
                tactic_id = tactic.get("id")
                if tactic_id and tactic_id not in tactics:
                    tactics.append(tactic_id)

            # Extract techniques - can be a list or single dict
            technique_data = threat_item.get("technique", [])

            # Normalize to list
            if isinstance(technique_data, dict):
                technique_list = [technique_data]
            elif isinstance(technique_data, list):
                technique_list = technique_data
            else:
                technique_list = []

            for technique in technique_list:
                if not isinstance(technique, dict):
                    continue

                # Get technique ID
                technique_id = technique.get("id")
                if technique_id and technique_id not in techniques:
                    techniques.append(technique_id)

                # Check for sub-techniques - can be list or single dict
                subtechnique_data = technique.get("subtechnique", [])
                if isinstance(subtechnique_data, dict):
                    subtechnique_list = [subtechnique_data]
                elif isinstance(subtechnique_data, list):
                    subtechnique_list = subtechnique_data
                else:
                    subtechnique_list = []

                for sub in subtechnique_list:
                    if isinstance(sub, dict):
                        sub_id = sub.get("id")
                        if sub_id and sub_id not in techniques:
                            techniques.append(sub_id)

        return {"tactics": tactics, "techniques": techniques}

    def _determine_log_source(self, file_path: Path, os_list: list) -> dict:
        """Determine log source from file path and OS list."""
        path_str = str(file_path).lower()

        product = "endpoint"
        category = "behavior"

        if "windows" in path_str or "windows" in [str(o).lower() for o in os_list]:
            product = "windows"
        elif "linux" in path_str or "linux" in [str(o).lower() for o in os_list]:
            product = "linux"
        elif "macos" in path_str or "macos" in [str(o).lower() for o in os_list]:
            product = "macos"
        elif "cross-platform" in path_str:
            product = "cross_platform"

        return {"product": product, "category": category}

    def _determine_severity(self, data: dict) -> str:
        """Determine severity based on actions."""
        actions = data.get("actions", [])

        # If there are process termination actions, it's likely high severity
        for action in actions:
            if isinstance(action, dict):
                action_type = action.get("action")
                if action_type in ["terminate_process", "block"]:
                    return "high"

        return "medium"
