"""Microsoft Sentinel detection rule parser."""

import logging
import json
import re
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule, SkippedRule
from app.services.mitre_tactic_inference import infer_tactics

logger = logging.getLogger(__name__)


# KQL table names follow `[A-Za-z_][A-Za-z0-9_]*`; custom logs end in
# `_CL`. The resolver uses the tables as its authoritative data-source
# signal, so only real statement heads may land here: an identifier that
# opens a statement or a parenthesised sub-query and is followed by a
# pipe. Continuation lines (`and X == 1`), `extend` targets and let-bound
# variable names used to slip through as "tables" and pushed real tables
# out of the old three-entry cap (#141).
_KQL_LEADING_KEYWORDS = frozenset({
    "let", "print", "search", "find", "union", "range", "exec", "set",
    "alias", "declare", "restrict", "pattern", "materialize", "toscalar",
    "datatable", "externaldata", "evaluate", "invoke", "where", "extend",
    "project", "summarize", "join", "lookup", "on", "by", "in", "and", "or",
    "not", "true", "false", "null",
})
_KQL_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# Strip KQL comments (`// ...` to end of line, `/* ... */` blocks) and
# `let X = ...;` bindings so the statement scan sees only query text.
_KQL_LINE_COMMENT = re.compile(r"//[^\n]*")
_KQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_KQL_LET_BINDING = re.compile(
    r"\blet\s+\w+\s*=\s*[^;]*;",
    re.IGNORECASE | re.DOTALL,
)
_KQL_LET_NAME = re.compile(r"\blet\s+(\w+)\s*[=(]")
# `let x = Table | ...;` and `materialize(Table | ...)`: the RHS head is a
# table only when a pipe follows it (calls like `dynamic(...)` are not).
_KQL_LET_HEAD = re.compile(rf"\blet\s+\w+\s*=\s*({_KQL_IDENT})\s*(?=\||;)")
_KQL_WRAPPED_HEAD = re.compile(rf"\b(?:materialize|toscalar)\s*\(\s*({_KQL_IDENT})\s*(?=\|)")
# A statement head: the identifier that opens the text or follows a `;`,
# itself followed by a pipe or the end of the statement.
_KQL_STATEMENT_HEAD = re.compile(rf"(?:^|;)\s*({_KQL_IDENT})\s*(?=\||;|\Z)")
# `( Table | ...)` opens a sub-query in join / union / lookup / in ().
_KQL_PAREN_HEAD = re.compile(rf"\(\s*({_KQL_IDENT})\s*(?=\|)")
# `union [isfuzzy=true] T1, T2` and `search in (T1, T2)` list their tables.
_KQL_UNION_LIST = re.compile(
    rf"\bunion\b(?:\s+(?:isfuzzy|withsource|kind)\s*=\s*\w+)*\s+({_KQL_IDENT}(?:\s*,\s*{_KQL_IDENT})*)"
)
_KQL_SEARCH_IN = re.compile(r"\bsearch\s+in\s*\(([^)]*)\)")
# `| join [kind=x] Table on Key` without parentheses.
_KQL_JOIN_BARE = re.compile(
    rf"\b(?:join|lookup)\b(?:\s+kind\s*=\s*\w+)?(?:\s+hint\.\w+\s*=\s*\w+)*\s+({_KQL_IDENT})\s+on\b"
)
_KQL_MAX_TABLES = 12

# Query filters that say WHICH vendor or channel a multi-vendor table is
# carrying: `CommonSecurityLog | where DeviceVendor == "Acronis"`,
# `SecurityAlert | where ProviderName == "IoTSecurity"`,
# `WindowsEvent | where Provider == "Microsoft-Windows-Sysmon"`. The
# resolver reads these before it believes the table (#141). Negated
# operators are not discriminators and are skipped on purpose.
_KQL_DISCRIMINATOR_FIELDS = (
    "DeviceVendor", "DeviceProduct", "ProviderName", "ProductName", "ResourceType",
    "ResourceProvider", "Category", "Provider", "Source", "EventSourceName", "ProcessName", "Facility",
)
_KQL_QUOTED = r"(?:\"[^\"\n]*\"|'[^'\n]*')"
_KQL_DISCRIMINATOR = re.compile(
    r"(?:\b(?:tolower|toupper|tostring)\s*\(\s*)?\b(" + "|".join(_KQL_DISCRIMINATOR_FIELDS) + r")\b\s*\)?\s*"
    r"(==|=~|has_cs|has_any|has_all|has|contains_cs|contains|startswith_cs|startswith|in~|in)\s*"
    r"(\(?\s*" + _KQL_QUOTED + r"(?:\s*,\s*" + _KQL_QUOTED + r")*)",
    re.IGNORECASE,
)


def _strip_kql(query: str) -> str:
    cleaned = _KQL_BLOCK_COMMENT.sub("", query)
    return _KQL_LINE_COMMENT.sub("", cleaned)


def _extract_kql_tables(query: str) -> list[str]:
    """Return the distinct table names a query reads, in first-seen order.

    A table is an identifier that heads a statement, a `let` binding, a
    parenthesised sub-query, a `union` / `search in` list or a bare
    `join ... on`, and is followed by a pipe (or ends the statement).
    KQL keywords, let-bound names and function calls never qualify.
    """
    if not query or not isinstance(query, str):
        return []
    cleaned = _strip_kql(query)
    let_names = {m.group(1) for m in _KQL_LET_NAME.finditer(cleaned)}

    # Collect (offset, identifier) so the result keeps document order:
    # the head table of the main statement stays first.
    found: list[tuple[int, str]] = []
    for rx in (_KQL_LET_HEAD, _KQL_WRAPPED_HEAD, _KQL_PAREN_HEAD, _KQL_JOIN_BARE):
        found.extend((m.start(1), m.group(1)) for m in rx.finditer(cleaned))
    # Statement heads are scanned with the let bindings blanked out so a
    # binding body cannot pose as the main statement; blanking (rather
    # than deleting) keeps the offsets aligned with `cleaned`.
    body = _KQL_LET_BINDING.sub(lambda m: " " * len(m.group(0)), cleaned)
    found.extend((m.start(1), m.group(1)) for m in _KQL_STATEMENT_HEAD.finditer(body))
    for rx in (_KQL_UNION_LIST, _KQL_SEARCH_IN):
        for m in rx.finditer(cleaned):
            group, base = m.group(1), m.start(1)
            for part in group.split(","):
                found.append((base + group.index(part), part.strip()))
    candidates = [ident for _, ident in sorted(found)]

    seen: set[str] = set()
    tables: list[str] = []
    for ident in candidates:
        if not ident or not re.fullmatch(_KQL_IDENT, ident):
            continue
        if ident.lower() in _KQL_LEADING_KEYWORDS or ident in let_names:
            continue
        if ident not in seen:
            seen.add(ident)
            tables.append(ident)
        if len(tables) >= _KQL_MAX_TABLES:
            break
    return tables


def _extract_kql_discriminators(query: str) -> dict[str, list[str]]:
    """Return `{field: [values]}` for the vendor / channel filters in a
    query (fields in `_KQL_DISCRIMINATOR_FIELDS`, values lower-cased,
    first-seen order). Only affirmative operators count."""
    if not query or not isinstance(query, str):
        return {}
    found: dict[str, list[str]] = {}
    for match in _KQL_DISCRIMINATOR.finditer(_strip_kql(query)):
        field = match.group(1).lower()
        values = found.setdefault(field, [])
        for quoted in re.findall(_KQL_QUOTED, match.group(3)):
            value = quoted[1:-1].strip().lower()
            if value and value not in values:
                values.append(value)
    return {k: v for k, v in found.items() if v}

# `Solutions/<vendor>/SolutionMetadata.json` carries the vendor package's
# own `providers` (vendor names) and `categories.domains` (Sentinel's
# content-hub taxonomy). The sync fetches it for every solution (#138):
# cached once per repo root, attached to each rule as
# extra["solution_metadata"] = {"providers": [...], "domains": [...]}.
_SOLUTION_METADATA_CACHE: dict[str, dict[str, dict]] = {}
_RULE_TREE_MARKERS = ("/solutions/", "/detections/", "/asim/", "/summary rules/")


def _normalize_solution_domain(value: str) -> str:
    """Lower-case, and repair the mojibake dash some files carry
    (`Security � Network` -> `security - network`)."""
    text = re.sub(r"\s*[^\x00-\x7f]+\s*", " - ", str(value))
    return re.sub(r"\s+", " ", text).strip().lower()


def _load_solution_metadata(root: Path) -> dict[str, dict]:
    loaded: dict[str, dict] = {}
    solutions = root / "Solutions"
    if not solutions.is_dir():
        return loaded
    for meta_file in solutions.glob("*/SolutionMetadata.json"):
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8-sig"))
        except Exception:  # a malformed vendor file must not stop the sync
            continue
        if not isinstance(data, dict):
            continue
        categories = data.get("categories") if isinstance(data.get("categories"), dict) else {}
        providers = [p.strip() for p in (data.get("providers") or []) if isinstance(p, str) and p.strip()]
        domains = [
            _normalize_solution_domain(d) for d in (categories.get("domains") or []) if isinstance(d, str) and d.strip()
        ]
        loaded[meta_file.parent.name.lower()] = {"providers": providers, "domains": domains}
    return loaded


def _repo_root_of(file_path: str) -> str:
    """The clone root for an absolute rule path, `""` for a relative one."""
    text = str(file_path).replace("\\", "/")
    lower = text.lower()
    cut = min((i for i in (lower.find(m) for m in _RULE_TREE_MARKERS) if i > 0), default=-1)
    return text[:cut] if cut > 0 else ""


def _extract_solution_folder(file_path: str) -> str:
    """Return the vendor folder under `Solutions/<vendor>/...`, else "".

    Root-level Detections rules live in `Detections/<table>/…`; those
    don't have a vendor folder (the table name IS the signal), so this
    returns "" for them.
    """
    parts = str(file_path).replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "Solutions":
        return parts[1]
    return ""


def _extract_entity_types(entity_mappings) -> list[str]:
    """Return distinct `entityType` values from a rule's entityMappings.

    Sentinel supports Account, Host, FileHash, IP, URL, MailMessage,
    Process, CloudApplication, etc. Used as a last-resort fallback hint
    in the resolver when higher-precedence signals didn't fire.
    """
    if not isinstance(entity_mappings, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for em in entity_mappings:
        if not isinstance(em, dict):
            continue
        et = em.get("entityType")
        if isinstance(et, str) and et and et not in seen:
            seen.add(et)
            out.append(et)
    return out


_STUB_MARKERS = (
    "this file is moved to new location",
    "moved to new location",
    "this analytic rule is retired",
    "rule is retired",
    "has been deprecated",
    "is deprecated",
)


def _stub_reason(data) -> str | None:
    """Upstream leaves id/name/description/version stubs behind when a
    rule is moved into a Solution or retired; they carry no query."""
    if not isinstance(data, dict) or data.get("query"):
        return None
    desc = str(data.get("description") or "").lower()
    for marker in _STUB_MARKERS:
        if marker in desc:
            return "upstream stub (moved or retired)"
    if set(data) <= {"id", "name", "description", "version", "kind"}:
        return "upstream stub (no query)"
    return None


class SentinelParser(BaseParser):
    """Parser for Microsoft Sentinel Analytics Rules (YAML format)."""

    # Mapping of MITRE ATT&CK tactic names to IDs
    # Sentinel uses CamelCase or space-separated names
    TACTIC_MAPPING = {
        # CamelCase format (Sentinel style)
        "reconnaissance": "TA0043",
        "resourcedevelopment": "TA0042",
        "initialaccess": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilegeescalation": "TA0004",
        "defenseevasion": "TA0005",
        "credentialaccess": "TA0006",
        "discovery": "TA0007",
        "lateralmovement": "TA0008",
        "collection": "TA0009",
        "commandandcontrol": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
        # Space-separated format
        "resource development": "TA0042",
        "initial access": "TA0001",
        "privilege escalation": "TA0004",
        "defense evasion": "TA0005",
        "credential access": "TA0006",
        "lateral movement": "TA0008",
        "command and control": "TA0011",
    }

    @property
    def source_name(self) -> str:
        return "sentinel"

    def _remember_repo_root(self, file_path: str) -> None:
        """Ingestion calls can_parse with the absolute path: learn the
        clone root from it and load the solution metadata once."""
        root = _repo_root_of(file_path)
        if not root:
            return
        self._repo_root = root
        if root not in _SOLUTION_METADATA_CACHE:
            _SOLUTION_METADATA_CACHE[root] = _load_solution_metadata(Path(root))

    def _solution_metadata_for(self, folder: str) -> dict:
        root = getattr(self, "_repo_root", "")
        if not folder or not root:
            return {}
        return dict(_SOLUTION_METADATA_CACHE.get(root, {}).get(folder.lower(), {}))

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is a Sentinel detection rule file.

        Accepts rules from four locations:
          - `Solutions/<vendor>/Analytic Rules/*.yaml` (primary — vendor packages)
          - `Detections/<table>/*.yaml`               (root — grouped by KQL table name)
          - `ASIM/*/*.yaml`                           (ASIM-based detections)
          - `Summary rules/*.yaml`                    (alert-aggregation rules)

        Hunting / exploration / parser / workbook YAMLs live in parallel
        directories; we explicitly skip those because they're not detections.
        """
        path_str = str(file_path).replace("\\", "/").lower()
        self._remember_repo_root(str(file_path))

        # Must be YAML
        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False

        # Exclude non-rule YAMLs (hunting, workbooks, parsers, playbooks,
        # data connectors, sample data, etc.) and any test/deprecated paths.
        # Path-component match — substring matching falsely excluded
        # rule files that merely contained "test" in their filename.
        excluded_parts = {
            "tests", "test", "deprecated", ".git",
            "sample data", "workbooks", "parsers", "playbooks",
            "dataconnectors", "exploration queries",
            "hunting queries",  # hunting is distinct from detection
            "detection queries",  # same — these are hunting-style
            # ASIM ships parser templates / testers / convert-from
            # examples under `ASIM/dev/...` — scaffolding, not rules.
            # Audit surfaced 406 PARSE_NONE samples here; discovery
            # legitimately walks ASIM/** so the parser's exclusion is
            # the right place to skip them.
            "dev",
        }
        if self._is_in_excluded_dir(file_path, excluded_parts):
            return False
        # Files explicitly prefixed `test_` are also skipped — sentinel
        # repos sometimes ship sample/test fixtures next to real rules.
        if file_path.name.lower().startswith("test_"):
            return False

        # Accept any of the four rule-containing locations:
        if "/solutions/" in path_str and "/analytic rules/" in path_str:
            return True
        if path_str.startswith("detections/") or "/detections/" in path_str:
            # Guard against a rare `Solutions/<vendor>/Detections/` case —
            # already accepted above via the main branch if "Analytic Rules"
            # also appears. Only the root `Detections/` bucket gets here.
            return True
        if path_str.startswith("asim/") or "/asim/" in path_str:
            return True
        if "summary rules/" in path_str:
            return True

        return False

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse a Microsoft Sentinel Analytics YAML rule file."""
        try:
            data = yaml.safe_load(content)
            stub = _stub_reason(data)
            if stub:
                logger.debug(f"Skipping {file_path}: {stub}")
                return SkippedRule(stub)
            validated = self._validate_rule_shape(data, file_path, "name", "query")
            if validated is None:
                return None
            name, query = validated

            # Must be a Scheduled rule (not hunting query)
            kind = data.get("kind", "")
            if kind and kind.lower() not in ["scheduled", "nrt"]:
                logger.debug(f"Skipping {file_path}: not a scheduled rule (kind={kind})")
                return SkippedRule(f"kind={kind}")

            # Extract MITRE ATT&CK
            mitre_attack = self._extract_mitre(data)

            # Extract log source from requiredDataConnectors
            log_source = self._extract_log_source(data)

            # Extract tags
            tags = data.get("tags", []) or []
            if isinstance(tags, str):
                tags = [tags]

            # Extract severity
            severity = data.get("severity", "unknown")

            # Extract status. Azure-Sentinel templates carry a lifecycle
            # value -- `Available` (1,816 files, 65 with trailing
            # whitespace) or `Experimental` -- which the normalizer maps
            # to stable / experimental (#137). A template with no
            # `status` key is a published one, so the default is
            # `stable` rather than `unknown` (#47).
            status = data.get("status", "stable")

            # Description handling
            description = data.get("description", "")
            if isinstance(description, str):
                description = description.strip()

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=name,
                description=description,
                author="Microsoft",
                status=status,
                severity=severity,
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=query,
                false_positives=[],
                extra={
                    "id": data.get("id"),
                    "kind": kind,
                    "version": data.get("version"),
                    "queryFrequency": data.get("queryFrequency"),
                    "queryPeriod": data.get("queryPeriod"),
                    "triggerOperator": data.get("triggerOperator"),
                    "triggerThreshold": data.get("triggerThreshold"),
                    "requiredDataConnectors": data.get("requiredDataConnectors", []),
                    "entityMappings": data.get("entityMappings", []),
                    # Taxonomy-resolver inputs (Sentinel-specific tiers):
                    # Tier 1 — first KQL table names in the query head.
                    "kql_tables": _extract_kql_tables(query),
                    # Vendor / channel filters inside the query (#141):
                    # read before the table when the table is generic.
                    "kql_filters": _extract_kql_discriminators(query),
                    # Tier 4 — `Solutions/<vendor>/...` folder name.
                    "solution_folder": _extract_solution_folder(str(file_path)),
                    # Tier 4 -- the solution's own providers + domains (#138).
                    "solution_metadata": self._solution_metadata_for(
                        _extract_solution_folder(str(file_path))
                    ),
                    # Tier 5 — entity types (last-resort event_type hint).
                    "entity_types": _extract_entity_types(
                        data.get("entityMappings", [])
                    ),
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_mitre(self, data: dict) -> dict:
        """Extract MITRE ATT&CK tactics and techniques from Sentinel rule.

        Sentinel uses:
        - tactics: List of tactic names like ["Impact", "DefenseEvasion"]
        - relevantTechniques: List of technique IDs like ["T1565.001", "T1562.008"]
        """
        tactics = []
        techniques = []

        # Extract tactics. Use `or []` because Sentinel rules commonly
        # declare `tactics:` with an empty value (comment-only line
        # like `tactics: # pulled dynamically`) which YAML parses as
        # None, not []. The plain default arg only fires when the key
        # is ABSENT, so without this coerce the entire parse crashes
        # on `for tactic in None` -- 8 Sentinel Solutions rules were
        # silently dropped this way (Darktrace, Jamf Protect,
        # IronDefense, Trend Micro Vision One, ...).
        raw_tactics = data.get("tactics") or []
        if isinstance(raw_tactics, str):
            raw_tactics = [raw_tactics]

        for tactic in raw_tactics:
            if not isinstance(tactic, str):
                continue
            # Normalize tactic name (remove spaces, lowercase)
            normalized = tactic.lower().replace(" ", "").replace("-", "").replace("_", "")
            if normalized in self.TACTIC_MAPPING:
                tactic_id = self.TACTIC_MAPPING[normalized]
                if tactic_id not in tactics:
                    tactics.append(tactic_id)

        # Extract techniques. Same None-safety story as tactics above.
        raw_techniques = data.get("relevantTechniques") or []
        if isinstance(raw_techniques, str):
            raw_techniques = [raw_techniques]

        for technique in raw_techniques:
            if not isinstance(technique, str):
                continue
            # Normalize technique ID (ensure uppercase, T prefix)
            tech_id = technique.upper()
            if not tech_id.startswith("T"):
                tech_id = "T" + tech_id
            if tech_id not in techniques:
                techniques.append(tech_id)

        # Sentinel rules commonly declare `relevantTechniques` without a
        # matching `tactics` list. Infer tactics from the canonical
        # MITRE cache so those rules aren't left with empty tactics.
        if techniques:
            for tid in infer_tactics(techniques):
                if tid not in tactics:
                    tactics.append(tid)

        return {"tactics": tactics, "techniques": techniques}

    def _extract_log_source(self, data: dict) -> dict:
        """Extract log source information from requiredDataConnectors."""
        log_source = {
            "product": "azure",
            "category": "sentinel",
        }

        connectors = data.get("requiredDataConnectors", [])
        if not connectors:
            return log_source

        # Extract data types from connectors
        data_types = []
        connector_ids = []

        for connector in connectors:
            if isinstance(connector, dict):
                connector_id = connector.get("connectorId", "")
                if connector_id:
                    connector_ids.append(connector_id)

                types = connector.get("dataTypes", [])
                if isinstance(types, list):
                    data_types.extend(types)

        # Determine product from connector IDs
        connector_str = " ".join(connector_ids).lower()
        if "aws" in connector_str:
            log_source["product"] = "aws"
        elif "gcp" in connector_str or "google" in connector_str:
            log_source["product"] = "gcp"
        elif "office" in connector_str or "o365" in connector_str:
            log_source["product"] = "office365"
        elif "azuread" in connector_str or "entra" in connector_str:
            log_source["product"] = "azure_ad"
        elif "defender" in connector_str:
            log_source["product"] = "defender"

        if data_types:
            log_source["data_types"] = data_types

        return log_source
