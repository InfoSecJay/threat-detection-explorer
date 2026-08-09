"""LOLRMM detection rule parser (Sigma-based)."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)

# Digit-anchored so `attack.stealth` (a tactic short-name) doesn't
# false-match as software. Groups + software both follow
# `<letter><4+ digits>`.
LOLRMM_SOFTWARE_TAG_RE = re.compile(r"^attack\.s\d+")
LOLRMM_GROUP_TAG_RE = re.compile(r"^attack\.g\d+")


class LOLRMMParser(BaseParser):
    """Parser for LOLRMM detection rules (Sigma-compatible YAML format)."""

    @property
    def source_name(self) -> str:
        return "lolrmm"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a LOLRMM rule file."""
        path_str = str(file_path).lower()

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Must be in detections/sigma directory
        if "detections" not in path_str or "sigma" not in path_str:
            return False

        # Exclude test directories
        return not self._is_in_excluded_dir(file_path, {"tests", "test"})

    def _preprocess_yaml(self, content: str) -> str:
        """Preprocess YAML content to fix common issues in LOLRMM rules.

        LOLRMM rules often contain unquoted wildcards (*.domain.com) and
        environment variables (%programdata%) which are invalid YAML.
        This method quotes these values to make them parseable.
        """
        lines = content.split('\n')
        result = []

        for line in lines:
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                result.append(line)
                continue

            # Check if line contains a value that needs quoting
            # Pattern: key: value where value starts with * or contains %
            if ':' in line and not stripped.endswith(':'):
                # Split on first colon only
                colon_idx = line.index(':')
                key_part = line[:colon_idx + 1]
                value_part = line[colon_idx + 1:]

                # Check if value needs quoting
                value_stripped = value_part.strip()

                # Skip if already quoted or is a list marker or block scalar
                if (value_stripped.startswith('"') or
                    value_stripped.startswith("'") or
                    value_stripped.startswith('|') or
                    value_stripped.startswith('>')):
                    result.append(line)
                    continue

                # Quote values starting with * (YAML alias) or containing %
                if value_stripped.startswith('*') or '%' in value_stripped:
                    # Escape backslashes for JSON/YAML double-quoted strings
                    escaped_value = value_stripped.replace('\\', '\\\\')
                    # Preserve original indentation
                    leading_spaces = len(value_part) - len(value_part.lstrip())
                    quoted_value = ' ' * leading_spaces + '"' + escaped_value + '"'
                    result.append(key_part + quoted_value)
                    continue

            # Handle list items: - *value or - %value%
            if stripped.startswith('- '):
                item_value = stripped[2:].strip()
                # Skip if already quoted
                if item_value.startswith('"') or item_value.startswith("'"):
                    result.append(line)
                    continue
                # Quote if starts with * or contains %
                if item_value.startswith('*') or '%' in item_value:
                    # Escape backslashes for JSON/YAML double-quoted strings
                    escaped_value = item_value.replace('\\', '\\\\')
                    indent = len(line) - len(line.lstrip())
                    result.append(' ' * indent + '- "' + escaped_value + '"')
                    continue

            result.append(line)

        return '\n'.join(result)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a LOLRMM Sigma-format YAML rule file."""
        try:
            # Preprocess to fix invalid YAML (unquoted wildcards, env vars)
            preprocessed = self._preprocess_yaml(content)

            # LOLRMM rules can have multiple documents, take the first
            data = list(yaml.safe_load_all(preprocessed))
            if not data:
                return None
            rule = data[0]

            validated = self._validate_rule_shape(rule, file_path, "title", "detection")
            if validated is None:
                return None
            title, detection = validated

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

            # Add LOLRMM-specific tag
            non_mitre_tags = [t for t in tags if not self._is_mitre_tag(t)]
            if "lolrmm" not in [t.lower() for t in non_mitre_tags]:
                non_mitre_tags.append("lolrmm")

            # Extract status
            status = rule.get("status", "unknown")

            # Extract severity (called 'level' in Sigma)
            severity = rule.get("level", "unknown")

            # Extract false positives
            false_positives = rule.get("falsepositives", []) or []
            if isinstance(false_positives, str):
                false_positives = [false_positives]

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
                tags=non_mitre_tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=detection,
                false_positives=false_positives,
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
    TACTIC_MAPPING = {
        "reconnaissance": "TA0043",
        "resource_development": "TA0042",
        "initial_access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege_escalation": "TA0004",
        "defense_evasion": "TA0005",
        "credential_access": "TA0006",
        "discovery": "TA0007",
        "lateral_movement": "TA0008",
        "collection": "TA0009",
        "command_and_control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }

    def _is_mitre_tag(self, tag: str) -> bool:
        """Check if a tag is a MITRE ATT&CK reference."""
        tag_lower = tag.lower()

        # Check for technique/sub-technique IDs
        if tag_lower.startswith("attack.t"):
            return True

        # Check for software/tool references (S####) — digit-anchored
        # so tactic short-names like `attack.stealth` don't false-match.
        if LOLRMM_SOFTWARE_TAG_RE.match(tag_lower):
            return True

        # Check for group references (G####) — same anchoring.
        if LOLRMM_GROUP_TAG_RE.match(tag_lower):
            return True

        # Check for tactic names
        if tag_lower.startswith("attack."):
            tactic_name = tag_lower.replace("attack.", "")
            return tactic_name in self.TACTIC_MAPPING

        return False

    def _extract_mitre_from_tags(self, tags: list[str]) -> dict:
        """Extract MITRE ATT&CK tactics, techniques, groups, software from tags."""
        tactics = []
        techniques = []
        groups = []
        software = []

        for tag in tags:
            tag_lower = tag.lower()

            if tag_lower.startswith("attack.t"):
                # Technique ID (e.g., attack.t1059 or attack.t1059.001)
                technique_id = tag_lower.replace("attack.", "").upper()
                if technique_id not in techniques:
                    techniques.append(technique_id)

            elif LOLRMM_SOFTWARE_TAG_RE.match(tag_lower):
                # Software/tool ID (e.g. attack.s0002 -> S0002); digit-
                # anchored so `attack.stealth` etc. don't slip in.
                sid = tag_lower.replace("attack.", "").upper()
                if sid not in software:
                    software.append(sid)

            elif LOLRMM_GROUP_TAG_RE.match(tag_lower):
                # Group/actor ID (e.g. attack.g0016 -> G0016); same
                # anchoring.
                gid = tag_lower.replace("attack.", "").upper()
                if gid not in groups:
                    groups.append(gid)

            elif tag_lower.startswith("attack."):
                # Tactic name (e.g., attack.execution)
                tactic_name = tag_lower.replace("attack.", "")
                if tactic_name in self.TACTIC_MAPPING:
                    tactic_id = self.TACTIC_MAPPING[tactic_name]
                    if tactic_id not in tactics:
                        tactics.append(tactic_id)

        return {
            "tactics": tactics,
            "techniques": techniques,
            "groups": groups,
            "software": software,
        }
