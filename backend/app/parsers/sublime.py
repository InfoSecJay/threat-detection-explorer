"""Sublime Security detection rule parser."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule
from app.services.mitre_tactic_inference import infer_tactics

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
        return not self._is_in_excluded_dir(file_path, {"tests", "test"})

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Sublime YAML rule file."""
        try:
            data = yaml.safe_load(content)
            validated = self._validate_rule_shape(data, file_path, "name", "source")
            if validated is None:
                return None
            name, source_logic = validated

            # Extract MITRE tactics and techniques
            mitre_attack = self._extract_mitre(data)

            # Vendor-declared ids are rare in Sublime rules; when absent,
            # derive from attack_types and tag the provenance so derived
            # mappings stay distinguishable from vendor-declared ones.
            tags = data.get("tags", []) or []
            if not mitre_attack["techniques"]:
                derived = self._derive_techniques_from_attack_types(data)
                if derived:
                    mitre_attack["techniques"] = derived
                    for tactic_id in infer_tactics(derived):
                        if tactic_id not in mitre_attack["tactics"]:
                            mitre_attack["tactics"].append(tactic_id)
                    tags = list(tags) + ["mitre-mapping:derived"]

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
                tags=tags,
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

    # Derived ATT&CK mapping from Sublime's `attack_types` vocabulary
    # (teardown R10 / #108). Sublime publishes a small, stable email-threat
    # classification instead of ATT&CK ids; without this translation all
    # ~1,200 Sublime rules carry zero techniques -- concentrated exactly in
    # the initial-access/phishing space. The vocabulary is 7 values total,
    # so this table is exhaustive, not heuristic.
    ATTACK_TYPE_TECHNIQUES = {
        "credential phishing": ["T1566.002"],  # spearphishing link; refined to .001 on attachment signals
        "malware/ransomware": ["T1204.002"],   # user execution: malicious file
        "bec/fraud": ["T1656"],                # impersonation
        "callback phishing": ["T1566.004"],    # spearphishing voice (victim dials the number)
        "extortion": ["T1657"],                # financial theft
        "reconnaissance": ["T1598"],           # phishing for information
        # "spam" describes nuisance volume, not an ATT&CK behavior: no mapping.
    }

    # `tactics_and_techniques` values that indicate the phish arrives as an
    # attachment rather than a link, flipping T1566.002 -> T1566.001.
    ATTACHMENT_SIGNALS = {"pdf", "macros", "html smuggling", "image as content", "attachment"}

    def _derive_techniques_from_attack_types(self, data: dict) -> list[str]:
        """Map Sublime attack_types to ATT&CK techniques (mapping_origin: derived)."""
        attack_types = [
            a.strip().lower() for a in (data.get("attack_types") or []) if isinstance(a, str)
        ]
        tnt = {
            t.strip().lower() for t in (data.get("tactics_and_techniques") or []) if isinstance(t, str)
        }
        attachment_based = bool(tnt & self.ATTACHMENT_SIGNALS)
        techniques: list[str] = []
        for at in attack_types:
            for tid in self.ATTACK_TYPE_TECHNIQUES.get(at, []):
                if tid == "T1566.002" and attachment_based:
                    tid = "T1566.001"
                if tid not in techniques:
                    techniques.append(tid)
        return techniques

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
