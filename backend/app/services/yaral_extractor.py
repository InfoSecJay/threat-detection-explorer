"""YARA-L 2.0 (Google SecOps / Chronicle) field extractor (issue #6 tail).

Chronicle rules key on UDM paths inside the `events:` section:

    $e.metadata.event_type = "PROCESS_LAUNCH"
    strings.to_lower($e.target.process.command_line) = "..."
    re.regex($e.target.process.file.full_path, `\\\\powershell\\.exe$`) nocase
    $e.principal.ip in %corp_ranges
    $user = $e.principal.user.userid            // placeholder / join key

Extraction walks the events block only (match/outcome/condition are
aggregation + boolean glue), unwraps the scalar helpers, and records
one observable per `<udm path> OP <literal>` term. Placeholder
assignments and `%reference_list` membership record the FIELD without
a value (the value lives outside the rule). Multi-event rules (two or
more `$vars`) and `match:` windows mark the rule complex.

UDM path classification lives in field_extractor.FIELD_TYPE_MAP (UDM
block) with a small YARA-L-scope override map here for paths the
generic heuristics misread; `metadata.log_type` values become source
tables, numeric `product_event_type` values become event IDs,
non-numeric ones API actions (in Chronicle that field IS the cloud API
method).

Literal handling (2026-08-30 review):
  - Comments are stripped by a scanner that skips `"..."`, backtick and
    `/.../` regex literals, so `"https://..."` is never a comment.
  - Double-quoted literals are YARA-L escaped: `\\\\` and `\\"` are
    unescaped once. Backtick literals are raw.
  - Values that come from a regex (`= /.../`, `re.regex(...)`) keep
    their typed observable but stay off the flat surfaces
    (target_resources / api_actions / network_indicators / source
    tables), mirroring the whitespace / wildcard guards in
    field_extractor.
"""

from __future__ import annotations

import re

from app.services.field_extractor import (
    ExtractedFields,
    ExtractedObservable,
    _classify_field,
    _deduplicate_all,
    _extract_exe_names,
    _extract_registry_paths,
    _route_domain_fields,
)

_EVENTS_RE = re.compile(
    r"\bevents\s*:(.*?)(?=\n\s*(?:match|outcome|condition|options)\s*:|\Z)",
    re.DOTALL,
)
_MATCH_RE = re.compile(r"\n\s*match\s*:", re.IGNORECASE)

# `$var.some.udm.path` possibly ending in `["key"]` map access.
_PATH = r'\$[A-Za-z_]\w*\.(?P<path>(?:[a-z_]+\.)*[a-z_]+(?:\["[^"]+"\])?)'
_PATH_RE = re.compile(_PATH)

# Double-quoted literal body: YARA-L escapes with a backslash.
_DQ = r'"(?P<dq>(?:[^"\\]|\\.)*)"'

_SCALAR_WRAP_RE = re.compile(
    r"\bstrings\.(?:to_lower|to_upper|coalesce|concat)\s*\(\s*(" + _PATH + r")\s*\)"
)
# strings.contains($e.path, "x") / strings.starts_with / re.regex($e.path, `x`)
_TWO_ARG_RE = re.compile(
    r"\b(?P<neg>not\s+)?(?P<func>strings\.contains|strings\.starts_with|strings\.ends_with|"
    r"re\.regex|net\.ip_in_range_cidr)\s*\(\s*" + _PATH +
    r"\s*,\s*(?:" + _DQ + r"|`(?P<bt>[^`]*)`|'(?P<sq>[^']*)')\s*\)",
    re.IGNORECASE,
)
# $e.path OP literal   (literal: "str" | /regex/ | number)
_CMP_RE = re.compile(
    r"(?P<neg>\bnot\s+)?" + _PATH +
    r"\s*(?P<op>!=|=|<=|>=|<|>)\s*(?:" + _DQ +
    r"|/(?P<rx>(?:[^/\\]|\\.)*)/|(?P<num>-?\d+(?:\.\d+)?))",
    re.IGNORECASE,
)
# $e.path in ("a", "b")  |  $e.path in %list
_IN_RE = re.compile(
    r"(?P<neg>\bnot\s+)?" + _PATH + r"\s+in\s+(?:%(?P<ref>\w+)|\((?P<lit>[^)]*)\))",
    re.IGNORECASE,
)
_IN_LITERAL_RE = re.compile(_DQ)
# $placeholder = $e.path
_ASSIGN_RE = re.compile(r"\$\w+\s*=\s*" + _PATH + r"\s*$", re.MULTILINE)
_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)\.")

_CAP_VALUES = 50

# YARA-L-scope classification overrides. FIELD_TYPE_MAP / _classify_field
# are shared across every extractor; these paths are UDM-specific and
# the generic heuristics misread them (`"ip" in "relationship"` ->
# network, label VALUES -> cloud resources). Exact keys first, then
# prefix matches. Every pair must exist in taxonomy/canonical.py.
_YARAL_FIELD_MAP: dict[str, tuple[str, str]] = {
    # Entity graph edge verb (EXECUTES, OWNS, MEMBER_OF...): an event
    # relation, never a network indicator.
    "graph.relations.relationship": ("event", "event_action"),
}
_YARAL_PREFIX_MAP: tuple[tuple[str, tuple[str, str]], ...] = (
    # `target.resource.attribute.labels["visibility"] = "people_with_link"`
    # is a request parameter on the resource, not the resource itself.
    ("target.resource.attribute.labels.", ("cloud", "request_params")),
    # Prevalence statistics (day_count, rolling_max...) are file-scoped
    # numeric thresholds. canonical.py has no prevalence / threshold
    # subtype; pin the file fallback explicitly so the heuristic can
    # never drift onto a path surface.
    ("graph.entity.file.prevalence.", ("file", "file_field")),
)

# Characters after which a `/` opens a regex literal (`= /x/`, `(/x/`).
_REGEX_OPENERS = frozenset("=(,")


def _strip_comments(text: str) -> str:
    """Blank `//` line comments and `/* */` block comments, skipping
    `"..."` (backslash-escaped), backtick (raw) and `/.../` regex
    literals so their bodies are never mistaken for a comment.
    Newlines are preserved so line-anchored regexes still work."""
    out: list[str] = []
    i, n = 0, len(text)
    prev = ""  # last significant char emitted outside a literal
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                j += 1
            out.append(text[i:j + 1])
            i = j + 1
            prev = c
            continue
        if c == "`":
            j = text.find("`", i + 1)
            j = n - 1 if j < 0 else j
            out.append(text[i:j + 1])
            i = j + 1
            prev = c
            continue
        if c == "/":
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
                out.append(" ")
                i = j
                continue
            if nxt == "*":
                j = text.find("*/", i + 2)
                end = n if j < 0 else j + 2
                out.append(re.sub(r"[^\n]", " ", text[i:end]))
                i = end
                continue
            if prev in _REGEX_OPENERS:
                # Regex literal: runs to the next unescaped `/` on the
                # same line. No closer -> plain character.
                j = i + 1
                while j < n and text[j] not in "/\n":
                    if text[j] == "\\":
                        j += 1
                    j += 1
                if j < n and text[j] == "/":
                    out.append(text[i:j + 1])
                    i = j + 1
                    prev = "/"
                    continue
        out.append(c)
        if not c.isspace():
            prev = c
        i += 1
    return "".join(out)


def _unescape_dq(value: str) -> str:
    """YARA-L double-quoted literal -> matched value (`\\\\` -> `\\`,
    `\\"` -> `"`). Other escapes are left alone."""
    return re.sub(r'\\([\\"])', r"\1", value)


def _norm_path(path: str) -> str:
    """`additional.fields["msg_1"]` -> `additional.fields.msg_1`."""
    return re.sub(r'\["([^"]+)"\]', r".\1", path)


def _classify(field_name: str) -> tuple[str, str]:
    key = field_name.lower().strip()
    if key in _YARAL_FIELD_MAP:
        return _YARAL_FIELD_MAP[key]
    for prefix, pair in _YARAL_PREFIX_MAP:
        if key.startswith(prefix):
            return pair
    return _classify_field(field_name)


def _registry_surface(values: list[str]) -> list[str]:
    """field_extractor's registry surface check is case-sensitive on
    `\\CurrentVersion\\`; YARA-L rules routinely lowercase the key
    (`strings.to_lower(...)`), so match that hive path case-insensitively."""
    keys = _extract_registry_paths(values)
    for v in values:
        if v not in keys and "\\currentversion\\" in v.lower():
            keys.append(v)
    return keys


def _add(
    result: ExtractedFields, path: str, values: list[str], negated: bool,
    pattern: bool = False,
) -> None:
    """Record a field and, when values are present, its observable.

    `pattern` marks values that came from a regex body: the typed
    observable is kept (that is what the rule matches on) but the value
    never reaches a flat lookup surface.
    """
    field_name = _norm_path(path)
    result.fields_used.append(field_name)
    values = [v for v in values if v]
    if not values:
        return
    obs_type, obs_subtype = _classify(field_name)
    result.observables.append(
        ExtractedObservable(
            field=field_name, values=values, type=obs_type,
            subtype=obs_subtype, negated=negated,
        )
    )
    if obs_type == "process" and obs_subtype in (
        "process_name", "process_path", "parent_process_name", "parent_process_path",
    ):
        # Regex literals escape the dot (`powershell\.exe$`): unescape a
        # copy so the exe-name extractor still finds the binary.
        plain = [re.sub(r"\\(.)", r"\1", v) for v in values]
        result.process_names.extend(_extract_exe_names(values + plain))
    if obs_type == "file" and "path" in obs_subtype:
        result.file_paths.extend(v for v in values if ("\\" in v or "/" in v))
    if obs_type == "registry":
        result.registry_keys.extend(_registry_surface(values))
    if pattern:
        return
    if field_name.endswith("metadata.log_type"):
        result.source_tables.extend(values)
    if field_name.endswith("metadata.product_event_type"):
        for v in values:
            if v.isdigit():
                result.event_ids.append(v)
            elif re.match(r"^[A-Za-z][\w.:/-]*$", v):
                result.api_actions.append(v)
    if obs_type == "network":
        result.network_indicators.extend(
            v for v in values if not re.search(r"\s", v)
        )
    _route_domain_fields(obs_type, obs_subtype, values, negated, result)


def extract_yaral_fields(body: str) -> ExtractedFields:
    """Extract observables from a YARA-L rule body."""
    result = ExtractedFields()
    if not body or not isinstance(body, str):
        return result

    m = _EVENTS_RE.search(body)
    if not m:
        return result
    events = _strip_comments(m.group(1))

    # Complexity: event-variable count + match window + helper density.
    event_vars = set(_VAR_RE.findall(events))
    helper_calls = len(re.findall(r"\b(?:strings|re|net|math)\.\w+\s*\(", events))
    if len(event_vars) >= 2 or _MATCH_RE.search(body):
        result.query_complexity = "complex"
    elif helper_calls > 4 or events.count("\n") > 15:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    # Unwrap scalar helpers so the comparison regex sees the path.
    unwrapped = _SCALAR_WRAP_RE.sub(lambda mm: mm.group(1), events)

    # Two-arg helpers: strings.contains($e.path, "x") etc.
    for mm in _TWO_ARG_RE.finditer(unwrapped):
        if mm.group("dq") is not None:
            value = _unescape_dq(mm.group("dq"))
        else:
            value = mm.group("bt") or mm.group("sq") or ""
        is_regex = mm.group("func").lower() == "re.regex"
        _add(result, mm.group("path"), [value], bool(mm.group("neg")), pattern=is_regex)
    stripped = _TWO_ARG_RE.sub(" ", unwrapped)

    # Membership.
    for mm in _IN_RE.finditer(stripped):
        if mm.group("lit"):
            values = [_unescape_dq(x.group("dq")) for x in _IN_LITERAL_RE.finditer(mm.group("lit"))]
            _add(result, mm.group("path"), values, bool(mm.group("neg")))
        else:
            _add(result, mm.group("path"), [], False)  # %reference_list: field only
    stripped = _IN_RE.sub(" ", stripped)

    # Placeholder assignments record the field, no value.
    for mm in _ASSIGN_RE.finditer(stripped):
        _add(result, mm.group("path"), [], False)
    stripped = _ASSIGN_RE.sub(" ", stripped)

    # Direct comparisons against literals.
    for mm in _CMP_RE.finditer(stripped):
        is_regex = mm.group("rx") is not None
        if mm.group("dq") is not None:
            value = _unescape_dq(mm.group("dq"))
        elif is_regex:
            value = mm.group("rx")
        else:
            value = mm.group("num")
        op = mm.group("op")
        negated = bool(mm.group("neg")) or op == "!="
        if op in ("=", "!="):
            _add(result, mm.group("path"), [value or ""], negated, pattern=is_regex)
        else:
            _add(result, mm.group("path"), [], False)  # numeric range: field only

    # Any remaining path references (joins `$a.x = $b.y`, function args).
    for mm in _PATH_RE.finditer(stripped):
        name = _norm_path(mm.group("path"))
        if name not in result.fields_used:
            result.fields_used.append(name)

    result.observables = result.observables[:_CAP_VALUES]
    _deduplicate_all(result)
    return result
