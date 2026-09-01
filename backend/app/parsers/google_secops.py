"""Google SecOps (Chronicle) detection rule parser.

Chronicle rules use YARA-L 2.0 -- a YARA-inspired DSL with `rule <name>
{ meta: ... events: ... match: ... outcome: ... condition: ... }`
structure. We don't try to fully parse the DSL body; we extract the
`meta:` block (where author / mitre / platform / data_source / severity
live as `key = "value"` pairs) and pass the full body through as the
raw detection logic. Same shape every other parser produces.
"""

import logging
import re
from pathlib import Path
from typing import Optional

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)

# Regex to find `rule <name> {` at the top of the file. Captures the
# rule name token. YARA-L identifiers are letters/digits/underscores.
_RULE_HEADER = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.MULTILINE)

# `meta:` block runs from the `meta:` keyword to the next top-level
# section keyword (events / match / outcome / condition). We grep for
# the inside and then parse `key = "value"` pairs line-by-line.
_META_BLOCK = re.compile(
    r"\bmeta\s*:\s*(.+?)(?=\b(?:events|match|outcome|condition|options)\s*:)",
    re.DOTALL,
)

# `key = "value"` or `key = value` -- value is everything up to the
# end of the logical line. Multi-line string values are uncommon in
# the meta block; we treat each line as one entry. (No VERBOSE flag --
# literal `#` is part of the pattern for trailing-comment handling
# and conflicts with verbose-mode comment syntax.)
_META_PAIR = re.compile(
    r'^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*'
    r'(?:"(?P<dq>(?:[^"\\]|\\.)*)"'
    r"|'(?P<sq>(?:[^'\\]|\\.)*)'"
    r'|(?P<bare>[^\n#]+?))'
    r'[ \t]*(?:#.*)?$',
    re.MULTILINE,
)

# MITRE technique IDs anywhere in the rule (e.g. inside mitre_attack_url
# = "https://attack.mitre.org/techniques/T1078/004/"). The `/` is the
# sub-technique separator on the URL form. We also accept the
# T1078.004 dotted form in case a rule uses it in mitre_attack_technique.
_TECHNIQUE_FROM_URL = re.compile(r"techniques/(T\d{4})(?:/(\d{3}))?/?")
_TECHNIQUE_DOTTED = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Maps MITRE tactic display names -> tactic IDs. Chronicle rules use
# the display name in mitre_attack_tactic. Mirrors the table used by
# the Sigma parser but indexed by the MITRE-canonical name form.
TACTIC_NAME_TO_ID: dict[str, str] = {
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


class GoogleSecOpsParser(BaseParser):
    """Parser for Google SecOps (Chronicle) YARA-L 2.0 detection rules."""

    @property
    def source_name(self) -> str:
        return "google_secops"

    def can_parse(self, file_path: Path) -> bool:
        """Chronicle rules are `.yaral` files under `rules/community/`."""
        path_str = str(file_path).lower().replace("\\", "/")

        if not path_str.endswith(".yaral"):
            return False

        # Must be under rules/community/; skip _deprecated and tests.
        if "rules/community/" not in path_str:
            return False

        return not self._is_in_excluded_dir(
            file_path, {"_deprecated", "deprecated", "tests", "test", ".git"}
        )

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        try:
            header = _RULE_HEADER.search(content)
            if not header:
                logger.debug(f"Skipping {file_path}: no `rule <name> {{` header")
                return None
            rule_name = header.group(1)

            meta = self._extract_meta(content)
            if not meta:
                logger.debug(f"Skipping {file_path}: empty meta block")
                return None

            # `rule_name` / `description` / `author` are the meta fields
            # we care about for display; fall back to the parsed-out
            # rule identifier when `rule_name` isn't set.
            title = meta.get("rule_name") or rule_name
            description = meta.get("description")
            author = meta.get("author")

            severity = meta.get("severity") or meta.get("priority") or "unknown"

            # Chronicle's `status` analogue is `type` (Alert / Hunt /
            # Informational). Normalize "Alert" -> "stable" downstream.
            # meta `type` is the rule kind (alert / hunt), not a maturity;
            # Chronicle rules carry no lifecycle concept (teardown R09 / #107).
            status = "not_applicable"

            # Tags: collect a small set of useful meta fields.
            tags: list[str] = []
            for k in ("platform", "data_source", "type", "tactic"):
                v = meta.get(k)
                if v:
                    tags.append(v.lower().replace(" ", "_"))

            mitre_attack = self._extract_mitre(meta, content)

            # Detection logic is the full rule body (`{ ... }`) -- we
            # keep the original syntax so the rule renders verbatim in
            # the UI and the field extractor (when run) sees real text.
            body_start = header.end()
            depth = 1
            i = body_start
            while i < len(content) and depth > 0:
                ch = content[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            body = content[body_start:i - 1] if depth == 0 else content[body_start:]

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=description,
                author=author,
                status=status,
                severity=severity,
                log_source={
                    "platform": meta.get("platform"),
                    "data_source": meta.get("data_source"),
                },
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=body.strip(),
                false_positives=[],
                extra={
                    "rule_id": meta.get("rule_id"),
                    "rule_name": meta.get("rule_name"),
                    "type": meta.get("type"),
                    "platform": meta.get("platform"),
                    "data_source": meta.get("data_source"),
                    "mitre_attack_url": meta.get("mitre_attack_url"),
                    "mitre_attack_version": meta.get("mitre_attack_version"),
                    "priority": meta.get("priority"),
                    "references": meta.get("reference"),
                },
            )

        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_meta(self, content: str) -> dict:
        """Parse the YARA-L `meta:` block into a flat dict."""
        m = _META_BLOCK.search(content)
        if not m:
            return {}

        meta_text = m.group(1)
        out: dict = {}
        for pair in _META_PAIR.finditer(meta_text):
            key = pair.group(1).strip()
            val = pair.group("dq") or pair.group("sq") or (pair.group("bare") or "")
            val = val.strip()
            if not key:
                continue
            # Unescape common escapes inside double-quoted strings.
            val = val.replace("\\\"", "\"").replace("\\\\", "\\")
            out[key] = val
        return out

    def _extract_mitre(self, meta: dict, content: str) -> dict:
        """Pull tactics + techniques out of the Chronicle meta fields.

        Chronicle uses display names for tactics (`mitre_attack_tactic
        = "Initial Access"`) and a URL form for techniques
        (`mitre_attack_url = "https://attack.mitre.org/techniques/
        T1078/004/"`). Some rules also stash `T####.###` in
        `mitre_attack_technique_id`; we pick up either form.
        """
        tactics: list[str] = []
        techniques: list[str] = []

        tactic_field = (meta.get("mitre_attack_tactic") or "").lower().strip()
        if tactic_field:
            tid = TACTIC_NAME_TO_ID.get(tactic_field)
            if tid and tid not in tactics:
                tactics.append(tid)

        url = meta.get("mitre_attack_url") or ""
        m = _TECHNIQUE_FROM_URL.search(url)
        if m:
            base, sub = m.group(1), m.group(2)
            tid = f"{base}.{sub}" if sub else base
            if tid not in techniques:
                techniques.append(tid)

        # Some rules embed the dotted technique ID directly in a meta
        # field (mitre_attack_technique_id, etc.) instead of the URL.
        for k, v in meta.items():
            if "mitre" not in k.lower():
                continue
            for tid in _TECHNIQUE_DOTTED.findall(v or ""):
                if tid not in techniques:
                    techniques.append(tid)

        return {"tactics": tactics, "techniques": techniques}
