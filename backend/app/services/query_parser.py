"""Lucene-syntax query parser -> SQLAlchemy WHERE clause.

Powers the free-text search bar. Users type queries like:

    actor:apt29 AND severity:high
    (title:"cobalt strike" OR desc:"beacon") AND source:sigma
    tech:T1059.001 NOT platform:linux
    powershell             # bare word: multi-field substring

The syntax is Lucene-ish via `luqum`, translated to SQLAlchemy WHERE
clauses that work identically on SQLite (dev) and Postgres (prod).

Design principles:

- **Explicit field registry.** `QUERYABLE_FIELDS` is the ONE place
  aliases + columns + kinds live. The `/query/fields` endpoint reads
  this so the docs page stays in sync automatically.
- **Alias-friendly for MITRE.** `actor:APT29` resolves to `G0016` via
  the mitre_lookup groups table before matching. Same for
  `malware:Mimikatz` -> `S0002`. Users don't memorize IDs.
- **Fail loud, not silent.** Bad syntax -> `QueryParseError` with a
  position hint. Unknown fields -> suggestion (Levenshtein). No
  silent drops.
- **Bare words fall back** to multi-field substring across a curated
  set (title, description, tags) — matches user expectation from
  simple search bars.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from luqum.parser import parser as luqum_parser
from luqum.tree import (
    AndOperation,
    Fuzzy,
    Group,
    Item,
    Not,
    OrOperation,
    Phrase,
    Prohibit,
    Range,
    Regex,
    SearchField,
    UnknownOperation,
    Word,
)
from sqlalchemy import String, and_, cast, not_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.models.detection import Detection
from app.services.mitre_lookup import GROUPS as MITRE_GROUPS
from app.services.mitre_lookup import SOFTWARE as MITRE_SOFTWARE


class QueryParseError(ValueError):
    """Raised when a query string is malformed or references unknown fields."""

    def __init__(self, message: str, position: Optional[int] = None, suggestion: Optional[str] = None):
        self.message = message
        self.position = position
        self.suggestion = suggestion
        parts = [message]
        if position is not None:
            parts.append(f"(near position {position})")
        if suggestion:
            parts.append(f"did you mean '{suggestion}'?")
        super().__init__(" ".join(parts))


# ── Field registry ───────────────────────────────────────────────────
# The single source of truth. Both the parser (below) and the
# /query/fields endpoint (for the docs page) consume this. Add a new
# queryable dimension in one place and it appears everywhere.
#
# `kind` drives how we match:
#   "text"      - text column, ilike substring
#   "text_multi"- multiple text columns unioned (OR)
#   "list"      - JSON list column, quoted-substring ilike match
#   "list_substring" - JSON list column, UNquoted substring ilike: for the
#                 extracted-observable surfaces, where `process:powershell`
#                 should match `powershell.exe` and `path:\Temp\` any
#                 path containing it. Wildcards honored.
#   "list_mitre_group"    - JSON list of G-IDs; input can be ID or name
#   "list_mitre_software" - JSON list of S-IDs; input can be ID or name

@dataclass
class FieldSpec:
    aliases: list[str]
    kind: str
    columns: list[str]
    description: str
    examples: list[str] = field(default_factory=list)


QUERYABLE_FIELDS: list[FieldSpec] = [
    FieldSpec(
        aliases=["title", "name"],
        kind="text",
        columns=["title"],
        description="Rule title / display name.",
        examples=['title:"cobalt strike"', 'name:powershell'],
    ),
    FieldSpec(
        aliases=["desc", "description"],
        kind="text",
        columns=["description"],
        description="Rule description / summary.",
        examples=['desc:"credential access"'],
    ),
    FieldSpec(
        aliases=["content", "raw", "logic"],
        kind="text_multi",
        columns=["raw_content", "detection_logic"],
        description="Raw rule body + detection logic. Broadest text match.",
        examples=['content:"HKLM\\\\SOFTWARE"'],
    ),
    FieldSpec(
        aliases=["source"],
        kind="text",
        columns=["source"],
        description="Which upstream repo the rule came from.",
        examples=["source:sigma", "source:elastic"],
    ),
    FieldSpec(
        aliases=["sev", "severity"],
        kind="text",
        columns=["severity"],
        description="critical, high, medium, low, unknown.",
        examples=["sev:high", "severity:critical"],
    ),
    FieldSpec(
        aliases=["status"],
        kind="text",
        columns=["status"],
        description="stable, experimental, deprecated, unknown.",
        examples=["status:experimental"],
    ),
    FieldSpec(
        aliases=["lang", "language"],
        kind="text",
        columns=["language"],
        description="Rule query language (sigma, spl, esql, kql, eql, yara-l, ...).",
        examples=["lang:kql"],
    ),
    FieldSpec(
        aliases=["id", "rule", "rule_id"],
        kind="text",
        columns=["rule_id"],
        description="Vendor rule ID (UUID or vendor-specific string).",
        examples=["id:0f5f6b8a"],
    ),
    FieldSpec(
        aliases=["platform"],
        kind="list",
        columns=["platforms"],
        description="Canonical platform (windows, linux, macos, o365, aws, ...).",
        examples=["platform:windows", "platform:o365"],
    ),
    FieldSpec(
        aliases=["data", "datasource"],
        kind="list",
        columns=["data_sources"],
        description="Canonical data source (sysmon, auditd, cloudtrail, ...).",
        examples=["data:sysmon"],
    ),
    FieldSpec(
        aliases=["event", "eventtype"],
        kind="list",
        columns=["event_types"],
        description="Canonical event type (process, file, network, auth, ...).",
        examples=["event:process"],
    ),
    FieldSpec(
        aliases=["tactic"],
        kind="list",
        columns=["mitre_tactics"],
        description="MITRE ATT&CK tactic ID (TA0002 etc.).",
        examples=["tactic:TA0002"],
    ),
    FieldSpec(
        aliases=["tech", "technique"],
        kind="list",
        columns=["mitre_techniques"],
        description="MITRE ATT&CK technique ID (T1059, T1059.001).",
        examples=["tech:T1059", "technique:T1059.001"],
    ),
    FieldSpec(
        aliases=["actor", "group"],
        kind="list_mitre_group",
        columns=["mitre_groups"],
        description="ATT&CK Group. Accepts raw G-ID or a known name/alias.",
        examples=["actor:APT29", 'actor:"Cozy Bear"', "group:G0016"],
    ),
    FieldSpec(
        # `software` is the canonical name (matches the filter pills
        # and the /actors terminology, where tool|malware is a TYPE of
        # software). `tool:` / `malware:` still parse for old links.
        aliases=["software", "tool", "malware"],
        kind="list_mitre_software",
        columns=["mitre_software"],
        description="ATT&CK Software. Accepts raw S-ID or a known name.",
        examples=["software:Mimikatz", "software:S0154"],
    ),
    FieldSpec(
        aliases=["usecase", "story", "use_case"],
        kind="list",
        columns=["use_cases"],
        description="Vendor use-case / analytic-story label.",
        examples=['usecase:"Ransomware"'],
    ),
    FieldSpec(
        aliases=["tag"],
        kind="list",
        columns=["tags"],
        description="Free-form tag from the source rule.",
        examples=["tag:persistence"],
    ),
    # ── Extracted observables (issue: observables v2) ────────────────
    # The surfaces the per-source extractors populate. Substring match
    # so users type what they know (`powershell`, `\Temp\`, `.amazonaws`)
    # rather than the exact extracted token.
    FieldSpec(
        aliases=["process", "proc", "exe"],
        kind="list_substring",
        columns=["extracted_process_names"],
        description="Process / executable name the rule keys on.",
        examples=["process:powershell", "exe:certutil.exe"],
    ),
    FieldSpec(
        aliases=["path", "file", "filepath"],
        kind="list_substring",
        columns=["extracted_file_paths"],
        description="File path pattern the rule keys on.",
        examples=['path:"\Temp\\"', "file:.dll"],
    ),
    FieldSpec(
        aliases=["registry", "reg", "regkey"],
        kind="list_substring",
        columns=["extracted_registry_keys"],
        description="Registry key path the rule keys on.",
        examples=['registry:"CurrentVersion\Run"'],
    ),
    FieldSpec(
        aliases=["network", "ioc", "indicator", "ip", "domain"],
        kind="list_substring",
        columns=["extracted_network_indicators"],
        description="Network indicator (IP, domain, URL, port) the rule keys on.",
        examples=["domain:amazonaws.com", "ip:10.0.0"],
    ),
    FieldSpec(
        aliases=["action", "api", "apiaction"],
        kind="list_substring",
        columns=["extracted_api_actions"],
        description="Cloud / identity API action or event name the rule keys on.",
        examples=["action:CreateUser", "api:StopLogging"],
    ),
    FieldSpec(
        aliases=["eventid", "event_id", "eid"],
        kind="list",
        columns=["extracted_event_ids"],
        description="Vendor event ID (exact match) the rule keys on.",
        examples=["eventid:4688"],
    ),
    FieldSpec(
        aliases=["field", "fields"],
        kind="list_substring",
        columns=["extracted_fields_used"],
        description="Telemetry field name referenced by the rule logic.",
        examples=["field:CommandLine", "field:process.args"],
    ),
    FieldSpec(
        aliases=["table", "index", "logtype", "datamodel"],
        kind="list_substring",
        columns=["extracted_source_tables"],
        description="Source table / index / data model / log type the rule reads.",
        examples=["table:SecurityEvent", "datamodel:Endpoint.Processes"],
    ),
    FieldSpec(
        aliases=["resource", "target"],
        kind="list_substring",
        columns=["extracted_target_resources"],
        description="Cloud resource or identity target the rule keys on.",
        examples=["resource:arn:aws:iam"],
    ),
]

# ── Alias index (built once) ────────────────────────────────────────
_ALIAS_INDEX: dict[str, FieldSpec] = {}
for spec in QUERYABLE_FIELDS:
    for alias in spec.aliases:
        _ALIAS_INDEX[alias.lower()] = spec

# Fields a bare word (no colon) searches across. Curated to be useful,
# not exhaustive — dumping raw_content in here makes every query slow.
_BARE_WORD_FIELDS = ["title", "description", "tags"]


# ── MITRE alias resolution ──────────────────────────────────────────
# Build reverse indexes: name/alias -> G-ID and name -> S-ID. Case-
# insensitive. Users typing `actor:"Cozy Bear"` should hit G0016.

def _build_mitre_reverse() -> tuple[dict[str, str], dict[str, str]]:
    groups: dict[str, str] = {}
    for gid, info in MITRE_GROUPS.items():
        groups[info["name"].lower()] = gid
        for alias in info.get("aliases", []):
            groups[alias.lower()] = gid
    software: dict[str, str] = {}
    for sid, info in MITRE_SOFTWARE.items():
        software[info["name"].lower()] = sid
    return groups, software


_MITRE_GROUP_REVERSE, _MITRE_SOFTWARE_REVERSE = _build_mitre_reverse()


def _resolve_mitre_group(value: str) -> str:
    """Turn 'APT29' / 'Cozy Bear' into 'G0016'; pass IDs through."""
    v = value.strip()
    if v.upper().startswith("G") and v[1:].isdigit():
        return v.upper()
    return _MITRE_GROUP_REVERSE.get(v.lower(), v)


def _resolve_mitre_software(value: str) -> str:
    """Turn 'Mimikatz' into 'S0002'; pass IDs through."""
    v = value.strip()
    if v.upper().startswith("S") and v[1:].isdigit():
        return v.upper()
    return _MITRE_SOFTWARE_REVERSE.get(v.lower(), v)


# ── Field-value -> SQL clause ───────────────────────────────────────
def _wildcard_to_like(value: str) -> tuple[str, bool]:
    """Convert Lucene `*`/`?` wildcards to SQL `%`/`_`. Returns (pattern, has_wildcard)."""
    if "*" in value or "?" in value:
        return value.replace("*", "%").replace("?", "_"), True
    return value, False


def _text_clause(column_name: str, raw_value: str) -> ColumnElement:
    """Text column ilike match. Bare value gets `%` on both sides.

    Non-string columns (e.g. the JSON `tags` column reached via the
    bare-word fallback) are cast to text first. SQLite stores JSON as
    text so a plain ILIKE happens to work there, but Postgres has no
    `json ILIKE` operator and the query 500s at execution time.
    """
    col = getattr(Detection, column_name)
    if not isinstance(col.type, String):
        col = cast(col, String)
    pattern, is_wild = _wildcard_to_like(raw_value)
    if is_wild:
        return col.ilike(pattern)
    return col.ilike(f"%{pattern}%")


def _list_clause(column_name: str, raw_value: str) -> ColumnElement:
    """JSON-list column: quoted-substring ilike so `T1059` doesn't match `T1059.001`.

    Same trick the SearchService uses everywhere else — portable
    across SQLite + Postgres by casting the JSON column to text.
    """
    col = getattr(Detection, column_name)
    return cast(col, String).ilike(f'%"{raw_value}"%')


def _list_substring_clause(column_name: str, raw_value: str) -> ColumnElement:
    """JSON-list column, unquoted substring: `process:powershell` hits
    `powershell.exe`.

    Wildcards mean "match a whole ELEMENT with this pattern": the JSON
    text is `["powershell.exe", "cmd.exe"]`, so `"` is the element
    boundary. `power*` -> `%"power%` (element starts with), `*.exe` ->
    `%.exe"%` (element ends with). A pattern anchored to the column
    text instead (`power%`) could never match past the leading `[`.
    """
    col = getattr(Detection, column_name)
    pattern, is_wild = _wildcard_to_like(raw_value)
    if not is_wild:
        return cast(col, String).ilike(f"%{pattern}%")
    core = pattern.strip("%")
    prefix = "%" if raw_value.startswith("*") else '%"'
    suffix = "%" if raw_value.endswith("*") else '"%'
    return cast(col, String).ilike(f"{prefix}{core}{suffix}")


def _apply_field(spec: FieldSpec, value: str) -> ColumnElement:
    """Build a WHERE clause for `field:value` given a FieldSpec."""
    if spec.kind == "list_substring":
        return _list_substring_clause(spec.columns[0], value)
    if spec.kind == "list_mitre_group":
        return _list_clause(spec.columns[0], _resolve_mitre_group(value))
    if spec.kind == "list_mitre_software":
        return _list_clause(spec.columns[0], _resolve_mitre_software(value))
    if spec.kind == "list":
        return _list_clause(spec.columns[0], value)
    if spec.kind == "text":
        return _text_clause(spec.columns[0], value)
    if spec.kind == "text_multi":
        return or_(*[_text_clause(c, value) for c in spec.columns])
    raise QueryParseError(f"internal error: unknown field kind {spec.kind!r}")


def _bare_word_clause(value: str) -> ColumnElement:
    """Bare word (no `field:` prefix): substring across curated fields."""
    return or_(*[_text_clause(c, value) for c in _BARE_WORD_FIELDS])


# ── Field-name suggestions ──────────────────────────────────────────
def _closest_field(name: str) -> Optional[str]:
    """Levenshtein-ish suggestion for typos. Only suggests if very close."""
    from difflib import get_close_matches
    matches = get_close_matches(name.lower(), list(_ALIAS_INDEX.keys()), n=1, cutoff=0.7)
    return matches[0] if matches else None


# ── AST walker ──────────────────────────────────────────────────────
def _walk(node: Item) -> ColumnElement:
    """Turn a luqum AST node into a SQLAlchemy WHERE clause."""
    if isinstance(node, SearchField):
        alias = node.name.lower()
        spec = _ALIAS_INDEX.get(alias)
        if spec is None:
            raise QueryParseError(
                f"unknown field '{node.name}'",
                suggestion=_closest_field(node.name),
            )
        # The value is a child node (Word, Phrase, ...). Extract the raw
        # text out. luqum's Phrase includes the surrounding quotes;
        # strip them.
        child = node.expr
        if isinstance(child, Phrase):
            value = child.value.strip('"')
        elif isinstance(child, Word):
            value = child.value
        elif isinstance(child, Range):
            raise QueryParseError(f"range queries not supported on field '{node.name}'")
        elif isinstance(child, (Regex, Fuzzy)):
            raise QueryParseError(f"regex / fuzzy syntax not supported on field '{node.name}'")
        else:
            raise QueryParseError(f"unsupported value shape after '{node.name}:'")
        return _apply_field(spec, value)

    if isinstance(node, Word):
        return _bare_word_clause(node.value)

    if isinstance(node, Phrase):
        return _bare_word_clause(node.value.strip('"'))

    if isinstance(node, AndOperation):
        return and_(*(_walk(c) for c in node.children))
    if isinstance(node, OrOperation):
        return or_(*(_walk(c) for c in node.children))
    # `foo bar` (no explicit AND) parses as UnknownOperation — treat as AND
    # for the intuitive "both terms must match" behavior.
    if isinstance(node, UnknownOperation):
        return and_(*(_walk(c) for c in node.children))
    if isinstance(node, Not):
        return not_(_walk(node.a))
    if isinstance(node, Prohibit):
        # `-field:value` — logical NOT of the child.
        return not_(_walk(node.a))
    if isinstance(node, Group):
        return _walk(node.expr)

    raise QueryParseError(f"unsupported query construct: {type(node).__name__}")


def parse_query(q: str) -> Optional[ColumnElement]:
    """Parse a user-supplied query string into a SQLAlchemy WHERE clause.

    Returns None for empty/whitespace-only input (caller treats as
    "no filter"). Raises QueryParseError for malformed queries or
    unknown fields; the API surfaces this as a 400.
    """
    q = (q or "").strip()
    if not q:
        return None
    try:
        tree = luqum_parser.parse(q)
    except Exception as e:
        # luqum's parse errors don't give us a clean position; wrap
        # with a general message and pass the message through.
        raise QueryParseError(f"could not parse query: {e}") from e
    return _walk(tree)


def field_reference() -> list[dict]:
    """Return the field registry in a JSON-serializable shape.

    Powers the /query/fields endpoint that hydrates the Query
    Reference docs page. Any field added to QUERYABLE_FIELDS shows
    up here automatically.
    """
    return [
        {
            "aliases": spec.aliases,
            "kind": spec.kind,
            "columns": spec.columns,
            "description": spec.description,
            "examples": spec.examples,
        }
        for spec in QUERYABLE_FIELDS
    ]
