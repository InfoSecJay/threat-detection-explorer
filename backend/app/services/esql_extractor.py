"""ES|QL extractor rebuild (issue #6 tail).

The previous extractor ran flat regexes over the whole query: EVAL /
STATS-`AS` / DISSECT / GROK targets leaked into fields_used as if they
were telemetry (251 `Esql.*` aliases in the 2026-08-28 corpus), the
`BY` clause was split on commas only so `DATE_TRUNC(5 minutes,
@timestamp)` shredded into `"@timestamp)"`, nothing validated field
names, and osquery SQL segments in hunting files (separated by `---`)
were parsed as ES|QL (`"f.mtime DESC;"`).

This version:
- splits `---`-separated segments and only reads ES|QL ones (`FROM` /
  `|` start), skipping SQL
- collects DERIVED names first (EVAL targets, STATS/RENAME `AS`
  aliases, DISSECT/GROK `%{captures}`) and excludes them everywhere
- reads aggregation function ARGS in STATS as fields, and unwraps
  function calls in BY (`DATE_TRUNC(5 minutes, @timestamp)` -> the
  field inside), with unit words dropped
- validates every candidate name against the ES|QL identifier shape
- keeps the term extraction (==, !=, LIKE/RLIKE, IN) and the existing
  surface routing via _add_elastic_observable

2026-08-30 semantic review of production hunting rules:
- comments are stripped by a quote-aware scanner, so `"/usr/x/*" or
  ... "/home/*/y"` is no longer read as one block comment and a `//`
  inside a URL literal no longer truncates the WHERE clause
- every string literal (double-quoted and triple-quoted) is masked to a
  sentinel before any regex runs; values are unmasked only when an
  observable is emitted, so literals (`aws.cloudtrail`, `svchost.exe`)
  never reach fields_used and a `|` inside a literal no longer splits
  the stage
- `FROM idx METADATA _id, _version` clips the METADATA clause instead
  of storing the metadata columns as source_tables
- `starts_with` / `ends_with` / `cidr_match` predicates and the `:`
  match operator produce observables like `==`; a leading `not`
  (also `NOT IN`, `NOT LIKE`) marks the observable negated
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from app.services.field_extractor import (
    ExtractedFields,
    _add_elastic_observable,
    _apply_event_action_domain,
    _deduplicate_all,
    resolve_event_action_domain,
)

_IDENT_RE = re.compile(r"^[A-Za-z_@][\w.@]*$")
_IDENT_FIND = re.compile(r"[A-Za-z_@][\w.@]*")
_KEYWORDS = frozenset({
    "and", "or", "not", "in", "like", "rlike", "is", "null", "true",
    "false", "as", "by", "asc", "desc", "nulls", "first", "last",
    "minutes", "minute", "hours", "hour", "seconds", "second", "days",
    "day", "weeks", "week", "months", "month", "years", "year",
    "count", "count_distinct", "sum", "avg", "min", "max", "median",
    "percentile", "values", "top", "date_trunc", "bucket", "to_upper",
    "to_lower", "to_string", "to_ip", "to_datetime", "coalesce",
    "concat", "length", "mv_count", "mv_expand", "case", "cidr_match",
    "starts_with", "ends_with", "replace", "split", "trim", "substring",
    "now", "date_diff", "date_format", "abs", "round", "greatest",
    "least", "st_contains", "to_integer", "to_long", "to_double",
    "left", "right", "locate", "mv_dedupe", "mv_slice", "mv_sort",
})
_EVAL_TARGET_RE = re.compile(r"(?:^|,)\s*([A-Za-z_@][\w.@]*)\s*=(?!=)")
_AS_ALIAS_RE = re.compile(r"\bAS\s+([A-Za-z_@][\w.@]*)", re.IGNORECASE)
_CAPTURE_RE = re.compile(r"%\{[^}]*?([A-Za-z_][\w.]*)\}")
_AGG_ARG_RE = re.compile(
    r"\b(?:count|count_distinct|sum|avg|min|max|median|values|top|percentile)\s*\(\s*([A-Za-z_@][\w.@]*)",
    re.IGNORECASE,
)

# --- string-literal masking ------------------------------------------------
#
# Every literal is replaced by `"<SENT>n<SENT>"` (quotes kept) before any
# regex runs. The sentinel is outside the identifier character class, so
# identifier scans cannot see literal bodies; term regexes match the
# uniform masked shape and unmask the body when a value is emitted.
_SENT = "\x01"
_MASKED = r'"' + _SENT + r"(\d+)" + _SENT + r'"'
_MASKED_FIND = re.compile(_MASKED)
_UNMASK_RE = re.compile(_SENT + r"(\d+)" + _SENT)
_JSON_EXTRACT_RE = re.compile(
    r"JSON_EXTRACT[(][ ]*[A-Za-z_][A-Za-z0-9_]*[ ]*,[ ]*" + _MASKED, re.IGNORECASE
)

# WHERE term shapes over masked text. A field is never preceded by an
# identifier char or `:` (so `x::keyword == "v"` does not yield `keyword`).
_FIELD = r"(?<![\w.@:])([\w.@]+)"
_STR_CMP_RE = re.compile(_FIELD + r"\s*(==|!=|:)\s*" + _MASKED)
_NUM_CMP_RE = re.compile(_FIELD + r"\s*==\s*(\d+)(?!\w)")
_LIKE_RE = re.compile(
    _FIELD + r"\s+(NOT\s+)?(?:LIKE|RLIKE)\s+" + _MASKED, re.IGNORECASE
)
_IN_RE = re.compile(_FIELD + r"\s+(NOT\s+)?IN\s*\(([^)]+)\)", re.IGNORECASE)
_FUNC_PRED_RE = re.compile(
    r"(NOT\s+)?\b(?:starts_with|ends_with|cidr_match)\s*\(\s*([A-Za-z_@][\w.@]*)\s*,([^)]*)\)",
    re.IGNORECASE,
)


def _literal_end(text: str, i: int) -> int:
    """Index one past the string literal that starts at text[i] == '\"'.
    Triple-quoted literals have no escapes; single-quoted honour `\\`."""
    n = len(text)
    if text.startswith('"""', i):
        end = text.find('"""', i + 3)
        return n if end < 0 else end + 3
    j = i + 1
    while j < n and text[j] != '"':
        if text[j] == "\\":
            j += 1
        j += 1
    return min(j + 1, n)


def _strip_comments(text: str) -> str:
    """Remove `//` line comments and `/* */` block comments, skipping
    string literals so `//` or `/*` inside quotes survives."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            end = _literal_end(text, i)
            out.append(text[i:end])
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end  # keep the newline
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            out.append(" ")
            i = n if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _mask_literals(text: str) -> tuple[str, list[str]]:
    """Replace each string literal with a sentinel; return the masked
    text and the literal bodies (as written, no unescaping)."""
    lits: list[str] = []
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == '"':
            end = _literal_end(text, i)
            body = text[i:end]
            if body.startswith('"""'):
                inner = body[3:-3] if body.endswith('"""') and len(body) >= 6 else body[3:]
            else:
                inner = body[1:-1] if body.endswith('"') and len(body) >= 2 else body[1:]
            out.append('"' + _SENT + str(len(lits)) + _SENT + '"')
            lits.append(inner)
            i = end
        else:
            out.append(text[i])
            i += 1
    return "".join(out), lits


def _unmask(text: str, lits: list[str]) -> str:
    return _UNMASK_RE.sub(lambda m: lits[int(m.group(1))], text)


def _valid(name: str, derived: set[str]) -> bool:
    return (
        bool(_IDENT_RE.match(name))
        and name.lower() not in _KEYWORDS
        and name not in derived
        # Elastic's rule convention: computed columns carry the `Esql.`
        # prefix -- derived by definition even when assigned elsewhere.
        and not name.lower().startswith("esql.")
        and not name.replace(".", "").isdigit()
    )


def _strip_parens(text: str) -> str:
    """Remove nested (...) groups so top-level commas are honest."""
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"\([^()]*\)", " ", text)
    return text


def _esql_segments(query: str) -> list[str]:
    """`---`-separated blocks that are actually ES|QL. Hunting files can
    leave a bare fence-language line (`sql` / `esql`) as the first line
    of a block; strip it before deciding."""
    out = []
    nl = chr(10)
    for seg in re.split("(?m)^[ ]*---+[ ]*$", query):
        lines = seg.strip().splitlines()
        while lines and lines[0].strip().lower() in ("sql", "esql", "kql", "eql"):
            lines = lines[1:]
        body = nl.join(lines)
        head = body.strip().lower()
        if head.startswith("from") or head.startswith("|"):
            out.append(body)
    return out


def extract_esql_fields_v2(
    query: str,
    indices: Iterable[str] = (),
    integrations: Iterable[str] = (),
    default_domain: Optional[str] = None,
) -> ExtractedFields:
    """See field_extractor.extract_elastic_fields for the context args."""
    result = ExtractedFields()
    if not query or not isinstance(query, str):
        return result

    query, lits = _mask_literals(_strip_comments(query.strip()))

    pipe_count = query.count("|")
    if pipe_count > 5 or re.search(r"\bENRICH\b", query, re.IGNORECASE):
        result.query_complexity = "complex"
    elif pipe_count > 2:
        result.query_complexity = "moderate"
    else:
        result.query_complexity = "simple"

    def values_in(masked: str) -> list[str]:
        return [lits[int(n)] for n in _MASKED_FIND.findall(masked)]

    for segment in _esql_segments(query):
        stages = [s.strip() for s in segment.split("|") if s.strip()]

        # Pass 1: derived names.
        derived: set[str] = set()
        for stage in stages:
            parts = stage.split(None, 1)  # any whitespace, not just space
            cmd, rest = parts[0], (parts[1] if len(parts) > 1 else "")
            c = cmd.lower()
            if c == "inline":  # INLINE STATS ... behaves like STATS
                nxt = rest.split(None, 1)
                if nxt and nxt[0].lower() == "stats":
                    c, rest = "stats", (nxt[1] if len(nxt) > 1 else "")
            if c in ("eval", "completion"):
                derived.update(_EVAL_TARGET_RE.findall(_strip_parens(rest)))
            elif c in ("stats", "rename", "inline"):
                derived.update(_AS_ALIAS_RE.findall(rest))
                if c == "stats":
                    agg_part = re.split(r"\bBY\b", rest, maxsplit=1, flags=re.IGNORECASE)[0]
                    derived.update(_EVAL_TARGET_RE.findall(_strip_parens(agg_part)))
            elif c in ("dissect", "grok"):
                # Captures live inside the pattern literal.
                derived.update(_CAPTURE_RE.findall(_unmask(rest, lits)))

        def add_field(name: str) -> None:
            if _valid(name, derived) and name not in result.fields_used:
                result.fields_used.append(name)

        def add_term(field_name: str, values: list[str], negated: bool) -> None:
            if values and _valid(field_name, derived):
                _add_elastic_observable(field_name, values, negated, result)

        # Pass 2: per-command extraction.
        for stage in stages:
            parts = stage.split(None, 1)  # any whitespace, not just space
            cmd, rest = parts[0], (parts[1] if len(parts) > 1 else "")
            c = cmd.lower()
            if c == "inline":  # INLINE STATS ... behaves like STATS
                nxt = rest.split(None, 1)
                if nxt and nxt[0].lower() == "stats":
                    c, rest = "stats", (nxt[1] if len(nxt) > 1 else "")
            if c == "from":
                rest = re.split(r"\bMETADATA\b", rest, maxsplit=1, flags=re.IGNORECASE)[0]
                for table in rest.split(","):
                    table = table.strip()
                    if table and re.fullmatch(r"[\w.*\-]+", table):
                        result.source_tables.append(table)
            elif c in ("keep", "drop"):
                for f in rest.split(","):
                    add_field(f.strip())
            elif c == "where":
                for field_name, op, idx in _STR_CMP_RE.findall(rest):
                    add_term(field_name, [lits[int(idx)]], op == "!=")
                for field_name, value in _NUM_CMP_RE.findall(rest):
                    add_term(field_name, [value], False)
                for field_name, neg, idx in _LIKE_RE.findall(rest):
                    add_term(field_name, [lits[int(idx)]], bool(neg))
                for field_name, neg, values_str in _IN_RE.findall(rest):
                    add_term(field_name, values_in(values_str), bool(neg))
                for neg, field_name, args in _FUNC_PRED_RE.findall(rest):
                    add_term(field_name, values_in(args), bool(neg))
                # Bare field references (is not null, function args).
                for ident in _IDENT_FIND.findall(_strip_parens(rest) + " " + rest):
                    if "." in ident or ident.startswith("@"):
                        add_field(ident)
            elif c == "eval":
                for idx in _JSON_EXTRACT_RE.findall(rest):
                    add_field(lits[int(idx)])
                for ident in _IDENT_FIND.findall(rest):
                    if "." in ident or ident.startswith("@"):
                        add_field(ident)
            elif c == "stats":
                parts = re.split(r"\bBY\b", rest, maxsplit=1, flags=re.IGNORECASE)
                for arg in _AGG_ARG_RE.findall(parts[0]):
                    add_field(arg)
                if len(parts) > 1:
                    for token in _strip_parens_keep_idents(parts[1]):
                        add_field(token)
            elif c in ("sort",):
                for token in rest.split(","):
                    token = re.sub(r"\s+(?:asc|desc|nulls\s+(?:first|last))\s*$", "", token.strip(), flags=re.IGNORECASE)
                    add_field(token)
            elif c in ("dissect", "grok", "mv_expand"):
                m = re.match(r"([A-Za-z_@][\w.@]*)", rest)
                if m:
                    add_field(m.group(1))

    _apply_event_action_domain(
        result,
        resolve_event_action_domain(result, indices, integrations, default_domain),
    )
    _deduplicate_all(result)
    return result


def _strip_parens_keep_idents(by_clause: str) -> list[str]:
    """BY tokens: bare fields as-is; function-wrapped entries yield the
    field identifiers inside (`DATE_TRUNC(5 minutes, @timestamp)` ->
    @timestamp), unit/keyword words dropped by _valid."""
    tokens: list[str] = []
    for entry in by_clause.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "(" in entry:
            tokens.extend(_IDENT_FIND.findall(entry))
        else:
            tokens.append(entry)
    return tokens
