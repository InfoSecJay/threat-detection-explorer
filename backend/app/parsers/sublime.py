"""Sublime Security detection rule parser."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


class SublimeParser(BaseParser):
    """Parser for Sublime Security detection rules (YAML format)."""

    @property
    def source_name(self) -> str:
        return "sublime"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Sublime rule file."""
        path_str = str(file_path).lower()

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Must be in detection-rules directory
        if "detection-rules" not in path_str:
            return False

        # Exclude test directories
        excluded = ["tests", "test"]
        return not any(ex in path_str.lower() for ex in excluded)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Sublime YAML rule file."""
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None

            # Required field: name
            name = data.get("name")
            if not name:
                logger.debug(f"Skipping {file_path}: no name")
                return None

            # Required field: source (detection logic)
            source_logic = data.get("source")
            if not source_logic:
                logger.debug(f"Skipping {file_path}: no source")
                return None

            # Extract MITRE tactics and techniques
            mitre_attack = self._extract_mitre(data)

            # Extract author from authors list
            authors = data.get("authors", [])
            author = None
            if authors and isinstance(authors, list) and len(authors) > 0:
                first_author = authors[0]
                if isinstance(first_author, dict):
                    author = first_author.get("name")
                elif isinstance(first_author, str):
                    author = first_author

            # Map severity
            severity = data.get("severity", "unknown")

            # Extract false positives (Sublime may not have this, but check)
            false_positives = data.get("false_positives", []) or []
            if isinstance(false_positives, str):
                false_positives = [false_positives]

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=name,
                description=data.get("description"),
                author=author,
                status="stable",  # Sublime doesn't have status field
                severity=severity,
                log_source={"product": "email", "category": "email_security"},
                tags=data.get("tags", []) or [],
                mitre_attack=mitre_attack,
                detection_logic_raw=source_logic,
                false_positives=false_positives,
                extra={
                    "id": data.get("id"),
                    "type": data.get("type"),
                    "references": data.get("references", []),
                    "attack_types": data.get("attack_types", []),
                    "detection_methods": data.get("detection_methods", []),
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    # Map tactic names to IDs (with variations including spaces and underscores)
    TACTIC_MAPPING = {
        "reconnaissance": "TA0043",
        "resource development": "TA0042",
        "resource_development": "TA0042",
        "initial access": "TA0001",
        "initial_access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege escalation": "TA0004",
        "privilege_escalation": "TA0004",
        "defense evasion": "TA0005",
        "defense_evasion": "TA0005",
        "credential access": "TA0006",
        "credential_access": "TA0006",
        "discovery": "TA0007",
        "lateral movement": "TA0008",
        "lateral_movement": "TA0008",
        "collection": "TA0009",
        "command and control": "TA0011",
        "command_and_control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }

    def _extract_mitre(self, data: dict) -> dict:
        """Extract MITRE ATT&CK tactics and techniques from Sublime rule."""
        tactics = []
        techniques = []

        # Sublime uses tactics_and_techniques field
        tnt = data.get("tactics_and_techniques", []) or []

        for item in tnt:
            if not isinstance(item, str):
                continue

            item_lower = item.lower()

            # Check if it's a technique ID (T#### or T####.###)
            if re.match(r'^t\d{4}(\.\d{3})?$', item_lower):
                technique_id = item.upper()
                if technique_id not in techniques:
                    techniques.append(technique_id)
            # Check if it's a tactic name
            elif item_lower in self.TACTIC_MAPPING:
                tactic_id = self.TACTIC_MAPPING[item_lower]
                if tactic_id not in tactics:
                    tactics.append(tactic_id)

        return {"tactics": tactics, "techniques": techniques}
