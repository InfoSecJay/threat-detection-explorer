"""Sigma detection rule parser."""

import logging
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


class SigmaParser(BaseParser):
    """Parser for SigmaHQ detection rules (YAML format)."""

    @property
    def source_name(self) -> str:
        return "sigma"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Sigma rule file."""
        path_str = str(file_path).lower()

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Must be in rules directory
        if "rules" not in path_str:
            return False

        # Exclude test and deprecated directories
        excluded = ["tests", "deprecated", "test"]
        return not any(ex in path_str.lower() for ex in excluded)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Sigma YAML rule file."""
        try:
            # Sigma rules can have multiple documents, take the first
            data = list(yaml.safe_load_all(content))
            if not data:
                return None
            rule = data[0]

            if not isinstance(rule, dict):
                return None

            # Required field: title
            title = rule.get("title")
            if not title:
                logger.debug(f"Skipping {file_path}: no title")
                return None

            # Required field: detection
            detection = rule.get("detection")
            if not detection:
                logger.debug(f"Skipping {file_path}: no detection")
                return None

            # Extract log source
            logsource = rule.get("logsource", {})
            log_source = {
                "product": logsource.get("product"),
                "category": logsource.get("category"),
                "service": logsource.get("service"),
            }

            # Extract tags and MITRE info
            tags = rule.get("tags", []) or []
            mitre_attack = self._extract_mitre_from_tags(tags)

            # Extract status
            status = rule.get("status", "unknown")

            # Extract severity (called 'level' in Sigma)
            severity = rule.get("level", "unknown")

            # Extract false positives
            false_positives = rule.get("falsepositives", []) or []

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=rule.get("description"),
                author=rule.get("author"),
                status=status,
                severity=severity,
                log_source=log_source,
                tags=[t for t in tags if not self._is_mitre_tag(t)],
                mitre_attack=mitre_attack,
                detection_logic_raw=detection,
                false_positives=false_positives if isinstance(false_positives, list) else [false_positives],
                extra={
                    "id": rule.get("id"),
                    "references": rule.get("references", []),
                    "date": rule.get("date"),
                    "modified": rule.get("modified"),
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    # Mapping of MITRE ATT&CK tactic names to IDs
    # Supports both hyphenated (Sigma style: initial-access) and underscored formats
    TACTIC_MAPPING = {
        # Hyphenated format (Sigma standard)
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
        # Underscored format (alternative)
        "resource_development": "TA0042",
        "initial_access": "TA0001",
        "privilege_escalation": "TA0004",
        "defense_evasion": "TA0005",
        "credential_access": "TA0006",
        "lateral_movement": "TA0008",
        "command_and_control": "TA0011",
    }

    def _normalize_tactic_name(self, tactic_name: str) -> str:
        """Normalize tactic name to handle both hyphen and underscore formats."""
        # Try the name as-is first, then try with hyphens replaced by underscores
        return tactic_name.replace("_", "-")

    def _is_mitre_tag(self, tag: str) -> bool:
        """Check if a tag is a MITRE ATT&CK reference."""
        tag_lower = tag.lower()

        # Check for technique/sub-technique IDs (attack.t1059, attack.t1059.001)
        if tag_lower.startswith("attack.t"):
            return True

        # Check for software/tool references (S####)
        if tag_lower.startswith("attack.s"):
            return True

        # Check for group references (G####)
        if tag_lower.startswith("attack.g"):
            return True

        # Check for tactic names (attack.initial-access, attack.execution, etc.)
        if tag_lower.startswith("attack."):
            tactic_name = tag_lower.replace("attack.", "")
            # Check both original and normalized versions
            return tactic_name in self.TACTIC_MAPPING or self._normalize_tactic_name(tactic_name) in self.TACTIC_MAPPING

        return False

    def _extract_mitre_from_tags(self, tags: list[str]) -> dict:
        """Extract MITRE ATT&CK tactics and techniques from Sigma tags.

        Sigma tags use the format:
        - attack.t1059 or attack.t1059.001 for techniques
        - attack.initial-access or attack.execution for tactics
        - attack.s0001 for software (ignored)
        - attack.g0001 for groups (ignored)
        """
        tactics = []
        techniques = []

        for tag in tags:
            tag_lower = tag.lower()

            if tag_lower.startswith("attack.t"):
                # Technique ID (e.g., attack.t1059 or attack.t1059.001)
                technique_id = tag_lower.replace("attack.", "").upper()
                if technique_id not in techniques:
                    techniques.append(technique_id)

            elif tag_lower.startswith("attack.s"):
                # Software/tool references (e.g., attack.s0001) - skip
                continue

            elif tag_lower.startswith("attack.g"):
                # Group references (e.g., attack.g0001) - skip
                continue

            elif tag_lower.startswith("attack."):
                # Tactic name (e.g., attack.execution, attack.initial-access)
                tactic_name = tag_lower.replace("attack.", "")

                # Try direct lookup first
                if tactic_name in self.TACTIC_MAPPING:
                    tactic_id = self.TACTIC_MAPPING[tactic_name]
                    if tactic_id not in tactics:
                        tactics.append(tactic_id)
                # Try normalized version (underscore to hyphen)
                else:
                    normalized = self._normalize_tactic_name(tactic_name)
                    if normalized in self.TACTIC_MAPPING:
                        tactic_id = self.TACTIC_MAPPING[normalized]
                        if tactic_id not in tactics:
                            tactics.append(tactic_id)

        return {"tactics": tactics, "techniques": techniques}
