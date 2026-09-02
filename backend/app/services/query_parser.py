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
    From,
    To,
    Regex,
    SearchField,
    UnknownOperation,
    Word,
)
from sqlalchemy import String, and_, cast, func, not_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.models.detection import Detection
from app.services.actor_matching import (
    is_ambiguous_name,
    is_case_sensitive_name,
    is_unmatchable_name,
    label_like_patterns,
    sql_like_patterns,
)
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
        description=(
            "Rule maturity, Sigma vocabulary: stable, test, experimental, "
            "deprecated, unsupported, unknown."
        ),
        examples=["status:stable", "status:test"],
    ),
    FieldSpec(
        aliases=["building_block", "bb", "signal_only"],
        kind="bool",
        columns=["is_building_block"],
        description=(
            "Building-block / signal-only rules (Elastic building_block_type, "
            "Panther CreateAlert: false): they feed other rules instead of "
            "alerting on their own. true / false."
        ),
        examples=["building_block:true", "NOT building_block:true"],
    ),
    FieldSpec(
        aliases=["quality", "hygiene", "score"],
        kind="int",
        columns=["quality_score"],
        description=(
            "Hygiene score 0-100 (metadata, ATT&CK mapping, specificity, docs, "
            "testability -- rule hygiene, not detection accuracy). Supports "
            "comparisons and ranges; unscored rules never match."
        ),
        examples=["quality:>=60", "hygiene:<40", "quality:[60 TO 79]", "score:80"],
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
        examples=['actor:"Salt Typhoon"', "actor:APT29", "actor:G1017"],
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
        kind="event_id",
        columns=["extracted_event_ids"],
        description=(
            "Windows event ID the rule keys on, namespaced by log channel "
            "(sysmon:1, security:4688, powershell:4104). A bare number "
            "matches that ID on any channel."
        ),
        examples=["eventid:security:4688", "eventid:sysmon:1", "eventid:4104"],
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


def _mitre_entity_clause(column_name: str, entity_id: str, info: Optional[dict]) -> ColumnElement:
    """`actor:` / `software:` with the actor page's DEDICATED semantics
    (issue #34): the raw ATT&CK ID in the tag column, OR an analytic
    story / use-case label equal to the name or an alias, OR the name
    or an alias in the rule title.

    Only the ID tag matched before, which returned nothing for actors
    vendors write rules for but tag by name -- `actor:"Salt Typhoon"`
    was 0 while the actor page counted 60 dedicated rules. SQL-only,
    so names the regex layer treats as risky (single English words,
    all-caps codenames, very short names) are skipped here; the ID tag
    still matches for those.
    """
    clauses = [_list_clause(column_name, entity_id)]
    if info:
        for name in [info.get("name", ""), *info.get("aliases", [])]:
            if (
                not name or len(name) < 4
                or is_unmatchable_name(name) or is_ambiguous_name(name) or is_case_sensitive_name(name)
            ):
                continue
            clauses.extend(Detection.title.ilike(p) for p in sql_like_patterns(name))
            clauses.extend(cast(Detection.use_cases, String).ilike(p) for p in label_like_patterns(name))
    return or_(*clauses) if len(clauses) > 1 else clauses[0]


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


_BOOL_TRUE = frozenset({"true", "yes", "1"})
_BOOL_FALSE = frozenset({"false", "no", "0"})


def _bool_clause(column_name: str, raw_value: str) -> ColumnElement:
    """`field:true` / `field:false` on a boolean column. NULL (rows
    that pre-date the column) counts as false on both sides."""
    col = getattr(Detection, column_name)
    v = raw_value.strip().strip('"').lower()
    if v in _BOOL_TRUE:
        return col.is_(True)
    if v in _BOOL_FALSE:
        return col.isnot(True)
    raise QueryParseError(
        f"'{column_name}' expects true or false, got {raw_value!r}",
        suggestion="Use building_block:true or building_block:false.",
    )


def _parse_int(field_name: str, node: Item) -> Optional[int]:
    """Integer out of a luqum Word (`*` = unbounded -> None)."""
    if not isinstance(node, Word):
        raise QueryParseError(f"'{field_name}' expects a number, got {node!r}")
    raw = node.value.strip()
    if raw == "*":
        return None
    try:
        return int(raw)
    except ValueError:
        raise QueryParseError(
            f"'{field_name}' expects a whole number, got {raw!r}",
            suggestion=f"Use {field_name}:>=60, {field_name}:<40 or {field_name}:[40 TO 79].",
        )


def _int_clause(spec: FieldSpec, field_name: str, child: Item) -> ColumnElement:
    """Comparison / range / equality on an integer column. NULL never
    matches (an unscored rule is neither above nor below a threshold)."""
    col = getattr(Detection, spec.columns[0])
    if isinstance(child, From):
        bound = _parse_int(field_name, child.a)
        if bound is None:
            return col.isnot(None)
        return col >= bound if child.include else col > bound
    if isinstance(child, To):
        bound = _parse_int(field_name, child.a)
        if bound is None:
            return col.isnot(None)
        return col <= bound if child.include else col < bound
    if isinstance(child, Range):
        low = _parse_int(field_name, child.low)
        high = _parse_int(field_name, child.high)
        clauses = [col.isnot(None)]
        if low is not None:
            clauses.append(col >= low if child.include_low else col > low)
        if high is not None:
            clauses.append(col <= high if child.include_high else col < high)
        return and_(*clauses)
    if isinstance(child, Word):
        return col == _parse_int(field_name, child)
    raise QueryParseError(f"unsupported value shape after '{field_name}:'")


def _apply_field(spec: FieldSpec, value: str) -> ColumnElement:
    """Build a WHERE clause for `field:value` given a FieldSpec."""
    if spec.kind == "int":
        return _int_clause(spec, spec.aliases[0], Word(value))
    if spec.kind == "bool":
        return _bool_clause(spec.columns[0], value)
    if spec.kind == "list_substring":
        return _list_substring_clause(spec.columns[0], value)
    if spec.kind == "list_mitre_group":
        gid = _resolve_mitre_group(value)
        return _mitre_entity_clause(spec.columns[0], gid, MITRE_GROUPS.get(gid))
    if spec.kind == "list_mitre_software":
        sid = _resolve_mitre_software(value)
        return _mitre_entity_clause(spec.columns[0], sid, MITRE_SOFTWARE.get(sid))
    if spec.kind == "list":
        return _list_clause(spec.columns[0], value)
    if spec.kind == "event_id":
        from app.services.taxonomy.event_ids import event_id_conditions

        conds = event_id_conditions(getattr(Detection, spec.columns[0]), [value])
        if not conds:
            raise QueryParseError(f"empty value for field '{spec.aliases[0]}'")
        return or_(*conds)
    if spec.kind == "text":
        return _text_clause(spec.columns[0], value)
    if spec.kind == "text_multi":
        return or_(*[_text_clause(c, value) for c in spec.columns])
    raise QueryParseError(f"internal error: unknown field kind {spec.kind!r}")


# Dialect for the CURRENT parse_query call. Set synchronously before the
# walk and read by _bare_word_clause; safe under asyncio because the
# walk contains no awaits (no interleaving between set and use).
_ACTIVE_DIALECT = "generic"


def _bare_word_clause(value: str) -> ColumnElement:
    """Bare word (no `field:` prefix).

    Postgres (#12 / teardown F13): weighted full-text match against the
    generated `search_vector` column (title A > rule_id B > description
    C > logic D) via websearch_to_tsquery -- so `ransomware` ranks a
    rule TITLED ransomware above one that merely mentions it in a
    comment. SQLite (dev) keeps the curated-field substring match.
    """
    if _ACTIVE_DIALECT == "postgresql":
        from sqlalchemy import literal_column

        return literal_column("detections.search_vector").op("@@")(
            func.websearch_to_tsquery("english", value)
        )
    return or_(*[_text_clause(c, value) for c in _BARE_WORD_FIELDS])


def free_text_terms(q: str) -> list[str]:
    """The bare (unfielded) words/phrases in a query, for ranking.

    `powershell source:sigma "encoded command"` -> ["powershell",
    "encoded command"]. Negated terms and everything under a field are
    excluded. Returns [] on any parse problem -- ranking is best-effort.
    """
    q = (q or "").strip()
    if not q:
        return []
    try:
        tree = luqum_parser.parse(q)
    except Exception:  # noqa: BLE001 -- unparsable queries just do not rank
        return []

    terms: list[str] = []

    def collect(node) -> None:
        if isinstance(node, (SearchField, Not, Prohibit)):
            return  # fielded or negated subtrees do not contribute rank terms
        if isinstance(node, Word):
            if node.value and not node.value.startswith("-"):
                terms.append(node.value)
            return
        if isinstance(node, Phrase):
            terms.append(node.value.strip('"'))
            return
        for child in getattr(node, "children", []) or []:
            collect(child)

    collect(tree)
    return terms


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
        if spec.kind == "int":
            # Numeric fields accept `>=60` / `<40` (luqum From / To),
            # `[60 TO 79]` ranges, or a bare number for equality (#39).
            return _int_clause(spec, node.name, child)
        if spec.kind == "event_id" and isinstance(child, SearchField) and isinstance(child.expr, Word):
            # `eventid:sysmon:1` -- luqum reads the channel prefix as a
            # nested field; fold it back into one namespaced value so
            # the natural spelling works unquoted.
            return _apply_field(spec, f"{child.name}:{child.expr.value}")
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


def parse_query(q: str, dialect: str = "generic") -> Optional[ColumnElement]:
    """Parse a user-supplied query string into a SQLAlchemy WHERE clause.

    Returns None for empty/whitespace-only input (caller treats as
    "no filter"). Raises QueryParseError for malformed queries or
    unknown fields; the API surfaces this as a 400. `dialect` selects
    the bare-word strategy (tsvector on postgresql, ILIKE otherwise).
    """
    global _ACTIVE_DIALECT
    _ACTIVE_DIALECT = dialect or "generic"
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
