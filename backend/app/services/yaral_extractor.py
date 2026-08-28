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
block); `metadata.log_type` values become source tables, numeric
`product_event_type` values become event IDs, non-numeric ones API
actions (in Chronicle that field IS the cloud API method).
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
_COMMENT_RE = re.compile(r"//[^\n]*")

# `$var.some.udm.path` possibly ending in `["key"]` map access.
_PATH = r'\$[A-Za-z_]\w*\.(?P<path>(?:[a-z_]+\.)*[a-z_]+(?:\["[^"]+"\])?)'
_PATH_RE = re.compile(_PATH)

_SCALAR_WRAP_RE = re.compile(
    r"\bstrings\.(?:to_lower|to_upper|coalesce|concat)\s*\(\s*(" + _PATH + r")\s*\)"
)
# strings.contains($e.path, "x") / strings.starts_with / re.regex($e.path, `x`)
_TWO_ARG_RE = re.compile(
    r"\b(?P<neg>not\s+)?(?P<func>strings\.contains|strings\.starts_with|strings\.ends_with|"
    r"re\.regex|net\.ip_in_range_cidr)\s*\(\s*" + _PATH +
    r"\s*,\s*(?:\"(?P<dq>[^\"]*)\"|`(?P<bt>[^`]*)`|'(?P<sq>[^']*)')\s*\)",
    re.IGNORECASE,
)
# $e.path OP literal   (literal: "str" | /regex/ | number)
_CMP_RE = re.compile(
    r"(?P<neg>\bnot\s+)?" + _PATH +
    r"\s*(?P<op>!=|=|<=|>=|<|>)\s*(?:\"(?P<dq>[^\"]*)\"|/(?P<rx>(?:[^/\\]|\\.)*)/|(?P<num>-?\d+(?:\.\d+)?))",
    re.IGNORECASE,
)
# $e.path in ("a", "b")  |  $e.path in %list
_IN_RE = re.compile(
    r"(?P<neg>\bnot\s+)?" + _PATH + r"\s+in\s+(?:%(?P<ref>\w+)|\((?P<lit>[^)]*)\))",
    re.IGNORECASE,
)
# $placeholder = $e.path
_ASSIGN_RE = re.compile(r"\$\w+\s*=\s*" + _PATH + r"\s*$", re.MULTILINE)
_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)\.")

_CAP_VALUES = 50


def _norm_path(path: str) -> str:
    """`additional.fields["msg_1"]` -> `additional.fields.msg_1`."""
    return re.sub(r'\["([^"]+)"\]', r".\1", path)


def _add(
    result: ExtractedFields, path: str, values: list[str], negated: bool
) -> None:
    field_name = _norm_path(path)
    result.fields_used.append(field_name)
    values = [v for v in values if v]
    if not values:
        return
    obs_type, obs_subtype = _classify_field(field_name)
    result.observables.append(
        ExtractedObservable(
            field=field_name, values=values, type=obs_type,
            subtype=obs_subtype, negated=negated,
        )
    )
    if field_name.endswith("metadata.log_type"):
        result.source_tables.extend(values)
    if field_name.endswith("metadata.product_event_type"):
        for v in values:
            if v.isdigit():
                result.event_ids.append(v)
            elif re.match(r"^[A-Za-z][\w.:/-]*$", v):
                result.api_actions.append(v)
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
        result.registry_keys.extend(_extract_registry_paths(values))
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
    events = _COMMENT_RE.sub(" ", m.group(1))

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
        value = mm.group("dq") or mm.group("bt") or mm.group("sq") or ""
        _add(result, mm.group("path"), [value], bool(mm.group("neg")))
    stripped = _TWO_ARG_RE.sub(" ", unwrapped)

    # Membership.
    for mm in _IN_RE.finditer(stripped):
        if mm.group("lit"):
            values = re.findall(r'"([^"]*)"', mm.group("lit"))
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
        value = mm.group("dq")
        if value is None:
            value = mm.group("rx") if mm.group("rx") is not None else mm.group("num")
        op = mm.group("op")
        negated = bool(mm.group("neg")) or op == "!="
        if op in ("=", "!="):
            _add(result, mm.group("path"), [value or ""], negated)
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
