"""Panther Labs `panther-analysis` rule parser.

Panther rules ship as **YAML metadata + Python detection sibling**:

    rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml
    rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.py

The YAML carries all metadata (RuleID, LogTypes, Severity, Reports,
Tags, Reference, Runbook, Tests, DedupPeriodMinutes, Threshold, ...).
The Python holds the actual detection function (`def rule(event): ...`).
We treat the Python source as `detection_logic` verbatim so the rule
detail view shows what the analyst would actually run.

Edge cases handled:
- **Correlation rules** (`AnalysisType: correlation_rule`) have no `.py`
  sibling and no `LogTypes` — best-effort ingest with the YAML
  `Detection:` block serialized as detection_logic + a synthetic
  logsource marker so the taxonomy resolver doesn't crash.
- **Declarative rules** (e.g. `github_repo_archived.yml`) use an inline
  `Detection:` block with Key/Condition/Value predicates — no `.py`.
  Same fallback as correlation rules.
- **Signal-only rules** (`CreateAlert: false` or `panther-signal` tag)
  are precursor rules that feed correlations. Stamped `experimental`
  status + `panther-signal` tag preserved. See issue #26 for the
  cross-source status vocabulary rework.
- **Deprecated rules** — RuleIDs listed in the repo-root
  `deprecated.txt` are stamped `status: deprecated`.
- **MITRE format** — Panther uses `TA####:T####` (colon-joined) inside
  `Reports.MITRE ATT&CK`. Split at parse time into our canonical
  `tactics` + `techniques` arrays.
- **Other Reports families** (CIS, PCI, SOC2, MITRE ATLAS, AZT, etc.)
  are preserved as prefixed tags (`report:cis`, `report:pci`) so they
  stay searchable without needing a new column.
"""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule
from app.services.rule_discovery import RuleDiscoveryService

logger = logging.getLogger(__name__)


# Panther MITRE tag shape: `TA0005:T1562.007` (tactic:technique).
# Sub-techniques carry a `.NNN` suffix. Anchored so we don't accept
# junk like "TA0005:something-else".
_PANTHER_MITRE_RE = re.compile(r"^(TA\d{4}):(T\d{4}(?:\.\d{3})?)$")


class PantherParser(BaseParser):
    """Parser for Panther Labs panther-analysis rules."""

    def __init__(self, discovery: Optional[RuleDiscoveryService] = None):
        """Panther needs the discovery service to read the `.py` sibling
        and the repo-root `deprecated.txt` file. Discovery is optional
        for testability — parser tests can construct without it and
        pass content directly."""
        self.discovery = discovery
        # Lazy-loaded set of deprecated RuleIDs. Populated on first
        # parse() call so tests without a discovery service just get
        # an empty set (no rules stamped deprecated).
        self._deprecated_ids: Optional[set[str]] = None

    @property
    def source_name(self) -> str:
        return "panther"

    def can_parse(self, file_path: Path) -> bool:
        """Every YAML under `rules/` is a candidate. The discovery
        pattern already filters to `rules/**/*.yml{,yaml}` so
        can_parse mostly just re-affirms + rejects non-YAML."""
        path_str = str(file_path).lower().replace("\\", "/")
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False
        if "rules/" not in path_str:
            return False
        return not self._is_in_excluded_dir(
            file_path, {"tests", "test", "deprecated", ".git"}
        )

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        try:
            rule = yaml.safe_load(content)
            if not isinstance(rule, dict):
                return None

            rule_id = rule.get("RuleID")
            display_name = rule.get("DisplayName") or rule_id or ""
            if not display_name:
                logger.debug(f"Panther rule missing DisplayName + RuleID: {file_path}")
                return None

            analysis_type = (rule.get("AnalysisType") or "rule").lower()

            # ── Detection logic ──────────────────────────────────
            # Prefer the .py sibling. Correlation rules + one
            # declarative rule have no .py; fall back to serializing
            # the YAML Detection block.
            py_source = self._load_sibling_py(file_path)
            if py_source:
                language = "python"
                detection_logic_raw = py_source
            elif analysis_type == "correlation_rule":
                # Declarative correlation over other rules' alerts: no
                # query language; the modality carries "correlation".
                language = "none"
                detection_logic_raw = self._serialize_yaml_block(rule.get("Detection"))
            else:
                # Declarative Detection block (Key/Condition/Value).
                # There is no query language we can honestly name here;
                # surface unknown loudly instead of minting the source
                # name as a language facet value (teardown R07 / B8).
                logger.warning(
                    "Panther rule has no .py sibling and is not a "
                    f"correlation rule; language unresolved: {file_path}"
                )
                language = "unknown"
                detection_logic_raw = self._serialize_yaml_block(rule.get("Detection"))

            # ── Log source ────────────────────────────────────────
            log_types = rule.get("LogTypes") or []
            if not isinstance(log_types, list):
                log_types = [log_types] if log_types else []
            # Synthetic logsource shape our taxonomy resolver expects.
            # `product` = the vendor family from the FIRST LogType
            # (`AWS.CloudTrail` -> `aws`); rest ride in `extra` so the
            # vendor resolver can enumerate all of them for multi-source
            # rules. Correlation rules end up with empty log_types.
            log_source: dict = {
                "product": log_types[0].split(".", 1)[0].lower() if log_types else None,
                "category": None,
                "service": None,
            }

            # ── MITRE (Reports.MITRE ATT&CK) ──────────────────────
            reports = rule.get("Reports") or {}
            mitre_raw = reports.get("MITRE ATT&CK") or []
            mitre_attack = self._extract_mitre(mitre_raw)

            # ── Tags: base tags + non-MITRE Reports as `report:*` ──
            base_tags = rule.get("Tags") or []
            if not isinstance(base_tags, list):
                base_tags = [str(base_tags)]
            base_tags = [str(t) for t in base_tags]
            # Non-MITRE report families become prefixed tags so they're
            # searchable via the standard tag filter. Keeps report data
            # visible without needing a new column.
            report_tags = [
                f"report:{family.lower().replace(' ', '_')}"
                for family in reports.keys()
                if family != "MITRE ATT&CK"
            ]

            # ── Signal-only rules ─────────────────────────────────
            # `CreateAlert: false` OR `panther-signal` tag both signal
            # a building-block / precursor rule. Preserve the flag
            # visibly + fold the status decision below.
            is_signal_only = (
                rule.get("CreateAlert") is False
                or "panther-signal" in [t.lower() for t in base_tags]
            )

            # ── Status resolution ─────────────────────────────────
            # Priority: explicit deprecated.txt > rule's own status
            # hints (Panther rules don't carry a `status` field — they
            # carry `Enabled: bool` which we respect only for
            # defaults). Signal-only is NOT a status: it rides along in
            # `extra["is_signal_only"]` and becomes
            # `is_building_block` (issue #26).
            if rule_id and self._is_deprecated(rule_id):
                status = "deprecated"
            elif rule.get("Enabled") is False:
                # Disabled-in-repo != deprecated, but not production
                # either — treat as experimental.
                status = "experimental"
            else:
                status = "stable"

            # ── LogTypes into `extra` so the vendor resolver can see
            # every one (multi-source rules like OneLogin + AWS + Zoom).
            # References list captured for the detail page.
            references = rule.get("Reference")
            if references and not isinstance(references, list):
                references = [references]

            false_positives = rule.get("Runbook") or []
            if isinstance(false_positives, str):
                false_positives = [false_positives]

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=display_name,
                description=rule.get("Description"),
                author=None,  # Panther rules don't carry an Author field.
                status=status,
                severity=rule.get("Severity", "unknown"),
                log_source=log_source,
                tags=base_tags + report_tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=detection_logic_raw,
                false_positives=false_positives,
                extra={
                    "id": rule_id,
                    "display_name": display_name,
                    "language": language,
                    "analysis_type": analysis_type,
                    "log_types": log_types,
                    "reference": references or [],
                    "runbook": rule.get("Runbook"),
                    "dedup_period_minutes": rule.get("DedupPeriodMinutes"),
                    "threshold": rule.get("Threshold"),
                    "create_alert": rule.get("CreateAlert"),
                    "enabled": rule.get("Enabled"),
                    "is_signal_only": is_signal_only,
                    "reports": reports,
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    # ── Helpers ────────────────────────────────────────────────────

    def _load_sibling_py(self, file_path: Path) -> Optional[str]:
        """Fetch the sibling .py detection body from the discovery
        service. Returns None for rules that have no sibling
        (correlation + declarative)."""
        if self.discovery is None:
            return None
        return self.discovery.get_sibling_content(
            "panther", file_path, ".py",
        )

    def _serialize_yaml_block(self, block) -> str:
        """Fallback detection-logic serialization for rules that don't
        have a .py sibling — dump the YAML detection block as text so
        the detail view still shows *something*."""
        if not block:
            return ""
        try:
            return yaml.dump(block, default_flow_style=False, sort_keys=False)
        except Exception:
            return str(block)

    def _extract_mitre(self, raw_list) -> dict:
        """Turn Panther's `TA####:T####(.###)?` items (or free-form
        strings with same shape) into our canonical
        {tactics, techniques, groups, software} dict.

        Comments in the YAML (e.g. `# T1562.007: Impair Defenses`)
        are stripped by the YAML parser already — we only see the
        matched value strings. Panther rules do NOT tag groups or
        software via this field.
        """
        tactics: list[str] = []
        techniques: list[str] = []
        if not isinstance(raw_list, list):
            return {"tactics": [], "techniques": [], "groups": [], "software": []}
        for item in raw_list:
            if not isinstance(item, str):
                continue
            m = _PANTHER_MITRE_RE.match(item.strip())
            if not m:
                continue
            tactic, technique = m.group(1), m.group(2)
            if tactic not in tactics:
                tactics.append(tactic)
            if technique not in techniques:
                techniques.append(technique)
        return {
            "tactics": tactics,
            "techniques": techniques,
            "groups": [],
            "software": [],
        }

    def _is_deprecated(self, rule_id: str) -> bool:
        """Check the repo-root `deprecated.txt` for this RuleID.

        The file is line-delimited with a mix of RuleIDs and prose
        descriptions (Panther's `deprecated.txt` isn't a strict machine
        format). We treat any exact-match on stripped lines as
        deprecated; that matches every RuleID entry and avoids false
        positives on the prose lines (which don't share Panther's
        dotted-ID shape).
        """
        if self._deprecated_ids is None:
            self._deprecated_ids = self._load_deprecated_ids()
        return rule_id in self._deprecated_ids

    def _load_deprecated_ids(self) -> set[str]:
        if self.discovery is None:
            return set()
        content = self.discovery.get_rule_content("panther", Path("deprecated.txt"))
        if not content:
            return set()
        ids: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            # Panther RuleIDs are dotted CamelCase — heuristic to
            # ignore prose lines. A RuleID always contains at least
            # one `.` and no whitespace.
            if line and "." in line and " " not in line:
                ids.add(line)
        return ids
