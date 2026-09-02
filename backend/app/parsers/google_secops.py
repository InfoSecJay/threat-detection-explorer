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
from app.services.mitre_tactic_inference import infer_tactics, technique_id_from_name

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
_TECHNIQUE_DOTTED = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TACTIC_ID = re.compile(r"TA\d{4}")

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

            # Tags: collect a small set of useful meta fields. `tactic`
            # is an ATT&CK id in this repo and goes to mitre_attack, not tags.
            tags: list[str] = []
            for k in ("platform", "data_source", "type"):
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

        The community repo uses two conventions side by side (#108 C6):

        - the newer, id-based `tactic = "TA0006"` / `technique =
          "T1003.001"` pair (~150 rules), and
        - the older display-name set: `mitre_attack_tactic = "Defense
          Evasion, Persistence"` (comma-separated, several tactics),
          `mitre_attack_technique = "Valid Accounts: Cloud Accounts"`,
          and `mitre_attack_url = ".../techniques/T1078/004/"`.

        Ids win wherever present; display names are resolved against
        the ATT&CK cache only when no id-form field gave us anything,
        so a name can never shadow a more specific id. Tactics missing
        from the meta are inferred from the techniques.
        """
        tactics: list[str] = []
        techniques: list[str] = []

        def add_tactic(tid: str) -> None:
            if tid and tid not in tactics:
                tactics.append(tid)

        def add_technique(tid: str) -> None:
            if tid and tid not in techniques:
                techniques.append(tid)

        for key in ("tactic", "mitre_attack_tactic", "mitre_attack_tactics"):
            for token in (meta.get(key) or "").split(","):
                token = token.strip()
                if not token:
                    continue
                if _TACTIC_ID.fullmatch(token.upper()):
                    add_tactic(token.upper())
                else:
                    add_tactic(TACTIC_NAME_TO_ID.get(token.lower(), ""))

        for base, sub in _TECHNIQUE_FROM_URL.findall(meta.get("mitre_attack_url") or ""):
            add_technique(f"{base}.{sub}" if sub else base)

        # Dotted ids in any technique-ish field (`technique`,
        # `mitre_attack_technique_id`, ...). Names-only fields simply
        # yield no matches here.
        for k, v in meta.items():
            kl = k.lower()
            if "technique" not in kl and "mitre" not in kl:
                continue
            if kl.endswith("url"):
                # Already handled above; the bare regex would also lift
                # the parent id out of ".../T1003/001/" as a second hit.
                continue
            for tid in _TECHNIQUE_DOTTED.findall(v or ""):
                add_technique(tid.upper())

        if not techniques:
            for token in (meta.get("mitre_attack_technique") or "").split(","):
                add_technique(technique_id_from_name(token) or "")

        if not tactics:
            for tid in infer_tactics(techniques):
                add_tactic(tid)

        return {"tactics": tactics, "techniques": techniques}
