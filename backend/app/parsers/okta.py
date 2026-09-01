"""Okta customer-detections rule parser.

Each detection is a single YAML file with this shape:

    title: <str>
    id: <hex hash>
    description: <multiline str>
    references: [<url>, ...]
    author: <str|list>
    created_date: <yyyy-mm-dd>
    modified_date: <yyyy-mm-dd>
    threat:
      Tactic: [<tactic name>, ...]
      Technique:
        - T1078: <name>            # may also be a bare dict
    prevention: [<str>, ...]
    detection:
      okta_systemlog:               # ONE of these three keying styles:
        OIE: <query>
        datadog: <query>
        explanation: <text>
      splunk: <query>               # OR directly under detection:
      explanation: <text>
      datadog: <query>              # OR
    false_positives: [<str>, ...]

A given rule typically carries one query language but some carry two
(OIE + datadog). We pick the primary in priority order:
    OIE -> spl -> datadog
so the rule lands as a single Detection row with one language tag.
The other query variants are kept in `extra` for the rule detail UI.
"""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


# Maps MITRE tactic display names (lowercase) -> tactic IDs. Okta YAML
# uses display names ("Initial Access", "Credential Access", etc.).
_TACTIC_NAME_TO_ID: dict[str, str] = {
    "reconnaissance":            "TA0043",
    "resource development":      "TA0042",
    "initial access":            "TA0001",
    "execution":                 "TA0002",
    "persistence":               "TA0003",
    "privilege escalation":      "TA0004",
    "defense evasion":           "TA0005",
    "credential access":         "TA0006",
    "discovery":                 "TA0007",
    "lateral movement":          "TA0008",
    "collection":                "TA0009",
    "command and control":       "TA0011",
    "exfiltration":              "TA0010",
    "impact":                    "TA0040",
}

# `T1078`, `T1078.004`, etc. Matches the dotted technique ID form.
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class OktaParser(BaseParser):
    """Parser for Okta customer-detections YAML rules."""

    @property
    def source_name(self) -> str:
        return "okta"

    def can_parse(self, file_path: Path) -> bool:
        """Okta detections live under `detections/*.yml` at the repo
        root. Sibling dirs (`hunts/`, `logs/`, `sample_osquery_checks/`,
        `tests/`, `workflows/`) are NOT analytic detections."""
        path_str = str(file_path).lower().replace("\\", "/")

        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False
        if "detections/" not in path_str:
            return False
        # Sibling top-level paths starting with `hunts/`, etc., never
        # contain "detections/". The condition above already excludes them.
        return not self._is_in_excluded_dir(
            file_path, {"hunts", "logs", "sample_osquery_checks", "tests", "test", "workflows", "deprecated", ".git"}
        )

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        try:
            data = yaml.safe_load(content)
            validated = self._validate_rule_shape(data, file_path, "title")
            if validated is None:
                return None
            title, _ = validated

            primary_lang, primary_query, all_queries = self._extract_queries(
                data.get("detection") or {}
            )
            if not primary_query:
                logger.debug(f"Skipping {file_path}: no detection query found")
                return None

            mitre = self._extract_mitre(data.get("threat") or {})

            # Author can be a string or list -- normalize to a single
            # display string (matching what we do for Elastic / Sentinel).
            author_raw = data.get("author")
            if isinstance(author_raw, list):
                author = ", ".join(str(a) for a in author_raw if a)
            elif isinstance(author_raw, str):
                author = author_raw
            else:
                author = None

            references = data.get("references") or []
            if not isinstance(references, list):
                references = [references] if references else []
            # Some rules have an explicit `null` entry in references.
            references = [r for r in references if r]

            false_positives = data.get("false_positives") or []
            if not isinstance(false_positives, list):
                false_positives = [false_positives] if false_positives else []

            # `prevention` is Okta-specific (mitigation guidance, sibling
            # to false_positives). Surface it via `extra` so the rule
            # detail UI can render it if/when we wire that.
            prevention = data.get("prevention") or []
            if not isinstance(prevention, list):
                prevention = [prevention] if prevention else []

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=data.get("description"),
                author=author,
                # Okta YAMLs don't carry status; community-published
                # detections in main branch are stable by convention.
                status="not_applicable",  # Okta rules carry no lifecycle concept (teardown R09 / #107)
                # Okta YAMLs don't carry severity; show that rather than
                # presenting a default as data (teardown R08 / #106).
                severity="unknown",
                log_source={
                    "product": "okta",
                    "category": "system_log",
                },
                # Detection block sub-keys (OIE / splunk / datadog) get
                # surfaced as tags so users can filter by query language.
                tags=[f"query:{lang}" for lang in all_queries.keys()],
                mitre_attack=mitre,
                detection_logic_raw=primary_query,
                false_positives=false_positives,
                extra={
                    "id": data.get("id"),
                    "references": references,
                    "created_date": data.get("created_date"),
                    "modified_date": data.get("modified_date"),
                    "primary_language": primary_lang,
                    "all_queries": all_queries,
                    "prevention": prevention,
                    "explanation": (data.get("detection") or {}).get("explanation"),
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_queries(self, detection: dict) -> tuple[str, str, dict[str, str]]:
        """Pull every query variant out of the `detection:` block.

        Returns ``(primary_language, primary_query, all_queries)``.
        Priority: OIE > spl > datadog. Empty strings if no query found.
        """
        all_queries: dict[str, str] = {}

        # Sub-keyed under okta_systemlog (25 of 34 rules).
        sys_log = detection.get("okta_systemlog")
        if isinstance(sys_log, dict):
            for key, val in sys_log.items():
                key_lower = key.lower()
                if key_lower in {"explanation"} or not isinstance(val, str):
                    continue
                # Inside okta_systemlog: `OIE`, `datadog`, sometimes `splunk`.
                lang = self._canonical_language(key_lower)
                if lang and val.strip():
                    all_queries.setdefault(lang, val.strip())

        # Direct keys under detection (splunk/datadog/OIE at top level).
        for key, val in detection.items():
            if not isinstance(val, str):
                continue
            key_lower = key.lower()
            if key_lower in {"explanation", "okta_systemlog"}:
                continue
            lang = self._canonical_language(key_lower)
            if lang and val.strip():
                all_queries.setdefault(lang, val.strip())

        # Pick primary by priority. `oie` > `spl` > `datadog`.
        for lang in ("oie", "spl", "datadog"):
            if lang in all_queries:
                return lang, all_queries[lang], all_queries

        return "", "", all_queries

    @staticmethod
    def _canonical_language(raw_key: str) -> str:
        """Map a detection-block key to a canonical language token."""
        if raw_key == "oie":
            return "oie"
        if raw_key in {"splunk", "spl"}:
            return "spl"
        if raw_key == "datadog":
            return "datadog"
        return ""

    def _extract_mitre(self, threat: dict) -> dict:
        """Pull tactic IDs + technique IDs out of the `threat:` block."""
        tactics: list[str] = []
        techniques: list[str] = []

        # Tactic: list of display names.
        for name in threat.get("Tactic") or []:
            if not isinstance(name, str):
                continue
            tid = _TACTIC_NAME_TO_ID.get(name.lower().strip())
            if tid and tid not in tactics:
                tactics.append(tid)

        # Technique: list of either `{Txxxx: name}` dicts or `Txxxx`
        # strings. PyYAML resolves `T1078: Valid Accounts` to a dict
        # with key `T1078`, so we collect the keys.
        for entry in threat.get("Technique") or []:
            if isinstance(entry, dict):
                for k in entry.keys():
                    key = str(k).strip()
                    if _TECHNIQUE_ID.match(key) and key not in techniques:
                        techniques.append(key)
            elif isinstance(entry, str):
                key = entry.strip()
                # Form might be `T1078` or `T1078: Valid Accounts`.
                if ":" in key:
                    key = key.split(":", 1)[0].strip()
                if _TECHNIQUE_ID.match(key) and key not in techniques:
                    techniques.append(key)

        return {"tactics": tactics, "techniques": techniques}
