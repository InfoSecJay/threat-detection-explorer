"""Splunk Security Content detection rule parser."""

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


def _normalize_security_domain(value: Any) -> str:
    """Coerce `tags.security_domain` to a single lowercase string.

    Splunk YAML sometimes ships it as a scalar, sometimes as a list
    (though only one value in practice). Taxonomy resolver does exact
    lookup so we flatten here.
    """
    if not value:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).lower().strip()


# Fields that historically lived under `tags:` in Splunk's schema but
# in the current schema (as of the 2025-2026 detection-format migration)
# frequently appear at the TOP LEVEL of the YAML with no `tags:` block
# at all. Every downstream extraction helper on this parser
# (_extract_mitre, _extract_tags, _derive_severity, _determine_log_source)
# reads from a single flattened `all_tags` dict, so promoting these
# fields lets the SAME code path handle both schemas. See
# https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_powgoop_beacon_decoding.yml
# for a live example of the new-schema shape.
_TOP_LEVEL_TAG_FIELDS = (
    "mitre_attack_id",
    "kill_chain_phases",
    "analytic_story",
    "asset_type",
    "security_domain",
    "context",
    "impact",
    "confidence",
    "risk_severity",
    "cve",
    "product",
    "custom_frameworks",
)


class SplunkParser(BaseParser):
    """Parser for Splunk Security Content detection rules (YAML format)."""

    @property
    def source_name(self) -> str:
        return "splunk"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Splunk detection rule file."""
        path_str = str(file_path).lower()

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Must be in detections directory
        if "detections" not in path_str:
            return False

        # Exclude deprecated and test directories
        return not self._is_in_excluded_dir(file_path, {"deprecated", "tests", "test"})

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Splunk YAML detection rule file."""
        try:
            data = yaml.safe_load(content)
            validated = self._validate_rule_shape(data, file_path, "name", "search")
            if validated is None:
                return None
            title, search = validated

            # Build the flattened tag dict FIRST -- every downstream
            # helper (_extract_mitre, _extract_tags, _derive_severity,
            # _determine_log_source) reads from it. Splunk's schema is
            # mid-migration: older rules keep everything under `tags:`,
            # newer rules (windows_powgoop_beacon_decoding, etc.) hoist
            # the same fields to the top level with no `tags:` block at
            # all. Promoting the fields listed in _TOP_LEVEL_TAG_FIELDS
            # makes the extractors schema-agnostic. Old-schema value
            # wins on conflict so rules mid-transition (both placements
            # populated) prefer the historically-authoritative nested
            # value.
            all_tags = dict(data.get("tags", {}) or {})
            for field in _TOP_LEVEL_TAG_FIELDS:
                if field in data and field not in all_tags:
                    all_tags[field] = data[field]

            # Extract MITRE ATT&CK from the merged tag dict so top-level
            # mitre_attack_id / kill_chain_phases in the new schema are
            # picked up.
            mitre_attack = self._extract_mitre(all_tags)

            tags = self._extract_tags(all_tags)

            # Derive severity from rba or tags. New-schema rules drop
            # the `rba:` block and instead put the risk score under
            # `finding.entity.score`. Synthesize an rba-shaped dict so
            # _derive_severity's existing risk-score logic works either
            # way.
            rba = data.get("rba", {}) or {}
            if not rba and "finding" in data:
                entity = (data.get("finding") or {}).get("entity")
                entities = entity if isinstance(entity, list) else [entity]
                risk_objects = [
                    {"score": e["score"]}
                    for e in entities
                    if isinstance(e, dict) and e.get("score") is not None
                ]
                if risk_objects:
                    rba = {"risk_objects": risk_objects}
            severity = self._derive_severity(all_tags, rba)

            # Determine log source from data model and tags
            log_source = self._determine_log_source(data, all_tags)

            # Extract status
            status = data.get("status", "unknown")

            # Author can be a string or list
            author = data.get("author")
            if isinstance(author, list):
                author = ", ".join(author)

            # Extract false positives
            known_fp = data.get("known_false_positives")
            false_positives = []
            if known_fp:
                if isinstance(known_fp, str):
                    false_positives = [known_fp]
                elif isinstance(known_fp, list):
                    false_positives = known_fp

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=data.get("description"),
                author=author,
                status=status,
                severity=severity,
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw={
                    "search": search,
                    "how_to_implement": data.get("how_to_implement"),
                },
                false_positives=false_positives,
                extra={
                    "id": data.get("id"),
                    "type": data.get("type"),
                    "data_source": data.get("data_source", []),
                    # Splunk's `tags.security_domain` is a coarse category
                    # (endpoint/network/identity/cloud/access/threat) the
                    # taxonomy resolver uses as a Tier 4 fallback. Value
                    # can be scalar or list — normalize to lowercase
                    # string for exact-match lookup.
                    "security_domain": _normalize_security_domain(
                        all_tags.get("security_domain")
                    ),
                    # Raw analytic_story values from the YAML (before
                    # the normalizer's story:snake_case flattening).
                    # The normalizer surfaces these on the canonical
                    # `use_cases` field with vendor-preserved casing.
                    # `all_tags` above merges the top-level value in
                    # so newer rules (top-level `analytic_story:`) and
                    # older rules (nested under `tags:`) both work.
                    "analytic_stories": all_tags.get("analytic_story", []) or [],
                    "references": data.get("references", []),
                    # `date` is the old-schema created field; new
                    # schema uses `creation_date` (and `modification_date`
                    # for updated). Fall back so both schemas produce
                    # a valid rule_created_date in the normalizer.
                    "date": data.get("date") or data.get("creation_date"),
                    "modification_date": data.get("modification_date"),
                    "cve": all_tags.get("cve", []),
                    "rba": rba,
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_mitre(self, tags: dict) -> dict:
        """Extract MITRE ATT&CK from Splunk detection.

        Args:
            tags: Flattened tag dict built in parse() -- already
                includes top-level promotions for the new schema.

        Returns:
            {"tactics": [...], "techniques": [...]}
        """
        tactics = []
        techniques = []

        # Get MITRE attack IDs
        mitre_ids = tags.get("mitre_attack_id", []) or []
        for mitre_id in mitre_ids:
            if not mitre_id:
                continue

            mitre_id_upper = mitre_id.upper()

            # Technique IDs start with T (e.g., T1059, T1059.001)
            if mitre_id_upper.startswith("T"):
                if mitre_id_upper not in techniques:
                    techniques.append(mitre_id_upper)
            # Tactic IDs start with TA (e.g., TA0002)
            elif mitre_id_upper.startswith("TA"):
                if mitre_id_upper not in tactics:
                    tactics.append(mitre_id_upper)

        # Get tactics from kill_chain_phases
        kill_chain = tags.get("kill_chain_phases", []) or []
        for phase in kill_chain:
            tactic_id = self._map_kill_chain_to_tactic(phase)
            if tactic_id and tactic_id not in tactics:
                tactics.append(tactic_id)

        # Always try to enrich tactics from techniques if we have techniques
        # This helps fill in missing tactics that weren't explicitly specified
        if techniques:
            inferred_tactics = self._infer_tactics_from_techniques(techniques)
            for tactic_id in inferred_tactics:
                if tactic_id not in tactics:
                    tactics.append(tactic_id)

        return {"tactics": tactics, "techniques": techniques}

    def _infer_tactics_from_techniques(self, techniques: list[str]) -> list[str]:
        """Infer likely tactics from technique IDs based on common mappings.

        This is a best-effort mapping for when tactics aren't explicitly provided.
        Uses the parent technique ID for sub-techniques.
        """
        # Common technique to tactic mappings (parent techniques only)
        technique_to_tactics = {
            # Execution
            "T1059": "TA0002",  # Command and Scripting Interpreter
            "T1106": "TA0002",  # Native API
            "T1053": "TA0002",  # Scheduled Task/Job
            "T1569": "TA0002",  # System Services
            "T1204": "TA0002",  # User Execution
            # Persistence
            "T1547": "TA0003",  # Boot or Logon Autostart Execution
            "T1037": "TA0003",  # Boot or Logon Initialization Scripts
            "T1098": "TA0003",  # Account Manipulation
            "T1136": "TA0003",  # Create Account
            "T1543": "TA0003",  # Create or Modify System Process
            # Privilege Escalation
            "T1548": "TA0004",  # Abuse Elevation Control Mechanism
            "T1134": "TA0004",  # Access Token Manipulation
            # Defense Evasion
            "T1140": "TA0005",  # Deobfuscate/Decode Files
            "T1070": "TA0005",  # Indicator Removal
            "T1036": "TA0005",  # Masquerading
            "T1027": "TA0005",  # Obfuscated Files
            "T1562": "TA0005",  # Impair Defenses
            # Credential Access
            "T1003": "TA0006",  # OS Credential Dumping
            "T1555": "TA0006",  # Credentials from Password Stores
            "T1110": "TA0006",  # Brute Force
            "T1558": "TA0006",  # Steal or Forge Kerberos Tickets
            # Discovery
            "T1087": "TA0007",  # Account Discovery
            "T1083": "TA0007",  # File and Directory Discovery
            "T1057": "TA0007",  # Process Discovery
            "T1012": "TA0007",  # Query Registry
            "T1018": "TA0007",  # Remote System Discovery
            # Lateral Movement
            "T1021": "TA0008",  # Remote Services
            "T1570": "TA0008",  # Lateral Tool Transfer
            # Collection
            "T1560": "TA0009",  # Archive Collected Data
            "T1005": "TA0009",  # Data from Local System
            "T1074": "TA0009",  # Data Staged
            # Command and Control
            "T1071": "TA0011",  # Application Layer Protocol
            "T1105": "TA0011",  # Ingress Tool Transfer
            "T1572": "TA0011",  # Protocol Tunneling
            # Exfiltration
            "T1041": "TA0010",  # Exfiltration Over C2 Channel
            "T1048": "TA0010",  # Exfiltration Over Alternative Protocol
            # Impact
            "T1486": "TA0040",  # Data Encrypted for Impact
            "T1489": "TA0040",  # Service Stop
            "T1490": "TA0040",  # Inhibit System Recovery
        }

        inferred_tactics = []
        for tech in techniques:
            # Extract parent technique ID (e.g., T1059 from T1059.001)
            parent_tech = tech.split(".")[0]
            if parent_tech in technique_to_tactics:
                tactic = technique_to_tactics[parent_tech]
                if tactic not in inferred_tactics:
                    inferred_tactics.append(tactic)

        return inferred_tactics

    def _map_kill_chain_to_tactic(self, phase: str) -> Optional[str]:
        """Map kill chain phase to MITRE ATT&CK tactic ID."""
        phase_lower = phase.lower()
        mapping = {
            "reconnaissance": "TA0043",
            "weaponization": "TA0042",
            "delivery": "TA0001",
            "exploitation": "TA0002",
            "installation": "TA0003",
            "command and control": "TA0011",
            "actions on objectives": "TA0040",
            # Additional common mappings
            "initial_access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege_escalation": "TA0004",
            "defense_evasion": "TA0005",
            "credential_access": "TA0006",
            "discovery": "TA0007",
            "lateral_movement": "TA0008",
            "collection": "TA0009",
            "exfiltration": "TA0010",
            "impact": "TA0040",
        }
        return mapping.get(phase_lower)

    def _extract_tags(self, tags: dict) -> list[str]:
        """Extract relevant tags from Splunk tags structure."""
        result = []

        # Extract analytic story - these are the detection use cases
        analytic_stories = tags.get("analytic_story", []) or []
        if isinstance(analytic_stories, str):
            analytic_stories = [analytic_stories]
        for story in analytic_stories:
            if story:
                result.append(f"story:{story}")

        # Extract asset type - what type of asset is being monitored
        asset_types = tags.get("asset_type", []) or []
        if isinstance(asset_types, str):
            asset_types = [asset_types]
        for asset in asset_types:
            if asset:
                result.append(f"asset:{asset}")

        # Extract security domain - threat, endpoint, network, etc.
        security_domain = tags.get("security_domain")
        if security_domain:
            if isinstance(security_domain, list):
                for domain in security_domain:
                    if domain:
                        result.append(f"domain:{domain}")
            else:
                result.append(f"domain:{security_domain}")

        return result

    def _derive_severity(self, tags: dict, rba: dict) -> str:
        """Derive severity from RBA risk score or tags.

        Args:
            tags: Tags dictionary from the rule
            rba: RBA (Risk-Based Alerting) configuration

        Returns:
            Severity string: low, medium, high, critical, or unknown
        """
        # First, try to get score from rba.risk_objects
        risk_objects = rba.get("risk_objects", []) or []
        if risk_objects:
            max_score = 0
            for risk_obj in risk_objects:
                if isinstance(risk_obj, dict):
                    score = risk_obj.get("score")
                    if score is not None:
                        try:
                            score_int = int(score)
                            if score_int > max_score:
                                max_score = score_int
                        except (ValueError, TypeError):
                            pass

            if max_score > 0:
                if max_score >= 80:
                    return "critical"
                elif max_score >= 60:
                    return "high"
                elif max_score >= 40:
                    return "medium"
                else:
                    return "low"

        # Fallback: try to derive from impact/confidence in tags
        impact = tags.get("impact")
        confidence = tags.get("confidence")

        if impact and confidence:
            try:
                avg = (int(impact) + int(confidence)) / 2
                if avg >= 80:
                    return "critical"
                elif avg >= 60:
                    return "high"
                elif avg >= 40:
                    return "medium"
                else:
                    return "low"
            except (ValueError, TypeError):
                pass

        # Check for risk_severity tag
        risk_severity = tags.get("risk_severity")
        if risk_severity:
            return risk_severity.lower()

        return "unknown"

    def _determine_log_source(self, data: dict, tags: dict) -> dict:
        """Determine log source from data model and tags."""
        log_source = {}

        # Get data source from detection
        data_sources = data.get("data_source", [])
        if data_sources:
            log_source["data_sources"] = data_sources

        # Determine product from tags
        asset_type = tags.get("asset_type", []) or []
        for asset in asset_type:
            asset_lower = asset.lower()
            if "endpoint" in asset_lower or "windows" in asset_lower:
                log_source["product"] = "windows"
                break
            elif "network" in asset_lower:
                log_source["product"] = "network"
                break
            elif "cloud" in asset_lower or "aws" in asset_lower:
                log_source["product"] = "cloud"
                break

        # Check context tags for more hints
        context = tags.get("context", []) or []
        for ctx in context:
            ctx_lower = ctx.lower()
            if "endpoint" in ctx_lower:
                log_source.setdefault("product", "endpoint")
            elif "network" in ctx_lower:
                log_source.setdefault("product", "network")

        return log_source
