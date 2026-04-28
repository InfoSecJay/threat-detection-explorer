"""Elastic detection rule parser."""

import logging
import re
import tomllib
from pathlib import Path
from typing import Optional

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


# ESQL queries embed their source in the query text itself — e.g.
# `FROM logs-aws.cloudtrail-* | where ...` — not in the separate
# `rule.index` field. We pull the indices out of the FROM clause so
# the taxonomy resolver can map them the same way as non-ESQL rules.
# ESQL FROM syntax supports:
#   FROM idx
#   FROM idx1, idx2
#   FROM "idx with spaces"
#   FROM idx METADATA _id, _index
#   from idx (case-insensitive)
_ESQL_FROM = re.compile(
    r"\bfrom\s+([^\|\n]+?)(?:\s+metadata\b|\s*\||\n|$)",
    re.IGNORECASE,
)


class ElasticParser(BaseParser):
    """Parser for Elastic detection rules (TOML format)."""

    @property
    def source_name(self) -> str:
        return "elastic"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is an Elastic rule file."""
        path_str = str(file_path).lower()

        # Must be TOML
        if not path_str.endswith(".toml"):
            return False

        # Must be in rules directory
        if "rules" not in path_str:
            return False

        # Exclude deprecated and test directories
        return not self._is_in_excluded_dir(
            file_path,
            {"_deprecated", "deprecated", "tests", "test", "_building_block"},
        )

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse an Elastic TOML rule file."""
        try:
            # tomllib (Python 3.11+ stdlib) handles modern TOML constructs
            # the legacy `toml` package chokes on with `IndexError: string
            # index out of range`. Switching recovered ~70 silently-dropped
            # AWS / cross-platform rules at first re-sync.
            data = tomllib.loads(content)
            if not isinstance(data, dict):
                return None

            # Get metadata + rule sections
            metadata = data.get("metadata", {})
            rule = data.get("rule", {})

            validated = self._validate_rule_shape(rule, file_path, "name")
            if validated is None:
                return None
            title = validated[0]

            # Detection logic is assembled from multiple TOML fields —
            # validate separately from _validate_rule_shape.
            detection_logic = self._extract_detection_logic(rule)
            if not detection_logic:
                logger.debug(f"Skipping {file_path}: no detection logic")
                return None

            # Extract MITRE ATT&CK from threat array
            mitre_attack = self._extract_mitre(rule.get("threat", []))

            # Extract severity
            severity = rule.get("severity", "unknown")

            # Extract tags
            tags = rule.get("tags", []) or []

            # Determine log source from index patterns or rule type
            log_source = self._determine_log_source(rule)

            # Map maturity to status
            status = self._map_maturity(metadata.get("maturity", "unknown"))

            # Extract false positives
            false_positives = rule.get("false_positives", []) or []
            if isinstance(false_positives, str):
                false_positives = [false_positives]

            # Index list: union of explicit `rule.index` + ESQL FROM-clause
            # extraction. ESQL rules embed their source in the query, so we
            # need to pull it out for the taxonomy resolver to see.
            explicit_indices = rule.get("index", []) or []
            if not isinstance(explicit_indices, list):
                explicit_indices = [explicit_indices]
            esql_indices = self._extract_esql_indices(rule)
            # Preserve original order, dedup
            seen = set()
            combined_indices: list[str] = []
            for idx in list(explicit_indices) + esql_indices:
                if isinstance(idx, str) and idx and idx not in seen:
                    seen.add(idx)
                    combined_indices.append(idx)

            # Rebuild log_source with the combined indices (overrides
            # _determine_log_source's original list).
            log_source["indices"] = combined_indices

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=rule.get("description"),
                author=rule.get("author", []),
                status=status,
                severity=severity,
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=detection_logic,
                false_positives=false_positives,
                extra={
                    "rule_id": rule.get("rule_id"),
                    "risk_score": rule.get("risk_score"),
                    "type": rule.get("type"),
                    "index": combined_indices,
                    # metadata.integration is critical for taxonomy
                    # resolution on rules that have no `rule.index` (ML,
                    # some ESQL). Previously dropped on the floor.
                    "integration": metadata.get("integration", []) or [],
                    "language": rule.get("language"),
                    "references": rule.get("references", []),
                    "creation_date": metadata.get("creation_date"),
                    "updated_date": metadata.get("updated_date"),
                    # `metadata.promotion = true` marks rules that wrap
                    # an external detection (Endgame / QRadar / AV /
                    # other SIEMs) as an Elastic alert. The taxonomy
                    # uses this to emit `platform_alert` event_type so
                    # the catalog distinguishes these from raw-telemetry
                    # rules and from SIEM-internal alert_correlation.
                    "promotion": bool(metadata.get("promotion", False)),
                    # Building-block rules don't fire alerts directly —
                    # they emit signal that other rules correlate. The
                    # field is set on the rule TOML when the author
                    # wants the rule treated this way; rules under the
                    # `rules_building_block/` tree are also building
                    # blocks by convention even when the field is unset.
                    # The normalizer combines both signals into a tag.
                    "building_block_type": rule.get("building_block_type"),
                },
            )

        except tomllib.TOMLDecodeError as e:
            logger.warning(f"TOML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_detection_logic(self, rule: dict) -> Optional[dict]:
        """Extract detection logic from rule depending on type."""
        rule_type = rule.get("type", "")

        if rule_type == "query":
            query = rule.get("query")
            if query:
                return {"type": "query", "query": query, "language": rule.get("language")}

        elif rule_type == "eql":
            query = rule.get("query")
            if query:
                return {"type": "eql", "query": query}

        elif rule_type == "threshold":
            query = rule.get("query")
            threshold = rule.get("threshold", {})
            if query:
                return {
                    "type": "threshold",
                    "query": query,
                    "threshold_field": threshold.get("field"),
                    "threshold_value": threshold.get("value"),
                }

        elif rule_type == "machine_learning":
            return {
                "type": "machine_learning",
                "anomaly_threshold": rule.get("anomaly_threshold"),
                "machine_learning_job_id": rule.get("machine_learning_job_id"),
            }

        elif rule_type == "new_terms":
            query = rule.get("query")
            new_terms = rule.get("new_terms", {})
            if query:
                return {
                    "type": "new_terms",
                    "query": query,
                    "field": new_terms.get("field"),
                    "history_window_start": new_terms.get("history_window_start"),
                }

        elif rule_type == "esql":
            query = rule.get("query")
            if query:
                return {"type": "esql", "query": query}

        # Fallback: try to get any query
        query = rule.get("query")
        if query:
            return {"type": rule_type or "unknown", "query": query}

        return None

    def _extract_mitre(self, threats) -> dict:
        """Extract MITRE ATT&CK from Elastic threat array.

        The TOML structure uses [[rule.threat]] for array of threat items, and
        [[rule.threat.technique]] creates nested arrays within each threat item.
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

        if not threats:
            return {"tactics": tactics, "techniques": techniques}

        # Ensure threats is a list
        threat_list = threats if isinstance(threats, list) else [threats]

        for threat in threat_list:
            if not isinstance(threat, dict):
                continue

            # Extract tactic (single dict per threat item)
            tactic = threat.get("tactic", {})
            if isinstance(tactic, dict):
                tactic_id = tactic.get("id")
                if tactic_id and tactic_id not in tactics:
                    tactics.append(tactic_id)

            # Extract techniques - can be a list or single dict
            technique_data = threat.get("technique", [])

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

                tech_id = technique.get("id")
                if tech_id and tech_id not in techniques:
                    techniques.append(tech_id)

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

    def _extract_esql_indices(self, rule: dict) -> list[str]:
        """Pull index patterns out of an ESQL query's FROM clause.

        ESQL rules don't populate `rule.index` — the source index is
        embedded in the query text (`FROM logs-foo-* | where ...`). This
        returns those indices as a list so the taxonomy resolver can map
        them like any other index pattern.

        Returns an empty list for non-ESQL rules or if no FROM clause
        can be located.
        """
        rule_type = rule.get("type", "")
        language = (rule.get("language") or "").lower()
        if rule_type != "esql" and language not in ("esql", "es|ql"):
            return []

        query = rule.get("query")
        if not isinstance(query, str) or not query:
            return []

        match = _ESQL_FROM.search(query)
        if not match:
            return []

        raw = match.group(1).strip()
        # Split on commas, strip quotes and whitespace from each entry.
        indices: list[str] = []
        for piece in raw.split(","):
            cleaned = piece.strip().strip('"').strip("'").strip()
            if cleaned:
                indices.append(cleaned)
        return indices

    def _determine_log_source(self, rule: dict) -> dict:
        """Determine log source from index patterns and rule metadata."""
        indices = rule.get("index", [])
        log_source = {"indices": indices}

        # Infer product from index patterns
        for index in indices:
            index_lower = index.lower()
            if "windows" in index_lower or "winlogbeat" in index_lower:
                log_source["product"] = "windows"
                break
            elif "linux" in index_lower or "auditbeat" in index_lower:
                log_source["product"] = "linux"
                break
            elif "cloud" in index_lower or "aws" in index_lower or "gcp" in index_lower or "azure" in index_lower:
                log_source["product"] = "cloud"
                break

        return log_source

    def _map_maturity(self, maturity: str) -> str:
        """Map Elastic maturity to normalized status."""
        maturity_lower = maturity.lower() if maturity else "unknown"
        mapping = {
            "production": "stable",
            "development": "experimental",
            "deprecated": "deprecated",
        }
        return mapping.get(maturity_lower, "unknown")
