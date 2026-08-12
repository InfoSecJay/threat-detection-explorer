"""Splunk Security Content detection rule parser."""

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule
from app.services.mitre_tactic_inference import infer_tactics

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
            # the `rba:` block and instead carry the integer risk score
            # under `finding.entity.score` (TTP / Correlation) or
            # `intermediate_findings.entities[].score` (Anomaly).
            # Synthesize an rba-shaped dict so _derive_severity's
            # existing risk-score logic works for every schema.
            rba = data.get("rba", {}) or {}
            if not rba:
                risk_objects = [
                    {"score": e["score"]}
                    for e in self._iter_finding_entities(data)
                    if isinstance(e, dict) and e.get("score") is not None
                ]
                if risk_objects:
                    rba = {"risk_objects": risk_objects}
            severity = self._derive_severity(all_tags, rba, data.get("type"))

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

        # Always enrich tactics from techniques when we have them.
        # Uses the shared MITRE cache (~835 techniques) instead of a
        # per-parser hardcoded table -- the previous 30-entry table
        # missed 45% of Splunk techniques and left them with empty
        # tactics on the site (audit ran 2026-08-11).
        if techniques:
            for tactic_id in infer_tactics(techniques):
                if tactic_id not in tactics:
                    tactics.append(tactic_id)

        return {"tactics": tactics, "techniques": techniques}

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

    @staticmethod
    def _iter_finding_entities(data: dict) -> list:
        """Collect entity dicts from the new-schema risk containers.

        Two shapes carry the integer risk score in the current schema:
          - `finding.entity` -- a single dict (TTP / Correlation)
          - `intermediate_findings.entities` -- a list (Anomaly)
        Either may also ship as a list; be permissive about both.
        """
        entities: list = []
        finding = data.get("finding")
        if isinstance(finding, dict):
            entity = finding.get("entity")
            entities.extend(entity if isinstance(entity, list) else [entity])
        inter = data.get("intermediate_findings")
        for block in inter if isinstance(inter, list) else [inter]:
            if isinstance(block, dict):
                ents = block.get("entities") or block.get("entity") or []
                entities.extend(ents if isinstance(ents, list) else [ents])
        return entities

    def _derive_severity(self, tags: dict, rba: dict, rule_type: str = "") -> str:
        """Derive severity from RBA risk score, tags, or rule type.

        Args:
            tags: Tags dictionary from the rule
            rba: RBA (Risk-Based Alerting) configuration (real or
                synthesized from finding / intermediate_findings)
            rule_type: The ESCU `type:` field (TTP, Anomaly, Hunting,
                Correlation, ...) -- used as the last-resort fallback

        Returns:
            Severity string: low, medium, high, or critical
        """
        # First, try to get score from rba.risk_objects
        risk_objects = rba.get("risk_objects", []) or []
        scores = []
        for risk_obj in risk_objects:
            if isinstance(risk_obj, dict):
                score = risk_obj.get("score")
                if score is not None:
                    try:
                        scores.append(int(score))
                    except (ValueError, TypeError):
                        pass

        if scores:
            max_score = max(scores)
            if max_score >= 80:
                return "critical"
            elif max_score >= 60:
                return "high"
            elif max_score >= 40:
                return "medium"
            elif max_score > 0:
                return "low"
            # max_score == 0: Correlation searches consume aggregated
            # risk rather than producing it and ship `score: 0` -- fall
            # through to the type fallback instead of calling them low.

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

        # Type-based fallback so every ESCU rule lands on a real
        # severity -- `unknown` silently excluded ~2,100 Splunk rows
        # from the severity facet. Correlation searches fire only after
        # aggregated risk crosses the Risk Notable threshold, so they
        # are high-fidelity alerts -> high. Hunting content is
        # informational by design, and anything else with no score
        # signal at all defaults with it -> low.
        if str(rule_type or "").lower() == "correlation":
            return "high"
        return "low"

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
