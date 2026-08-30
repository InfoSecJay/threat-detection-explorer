"""Okta System Log filter (OIE expression) extractor (issue #6 tail).

Okta customer detections carry a System Log search expression:

    eventType eq "user.risk.detect" and debugContext.debugData.risk co "level=HIGH"
    outcome.result ne "SUCCESS"
    client.ipAddress sw "10."
    eventType in ["system.api_token.create", "system.api_token.update"]
    not (target.detailEntry.MethodTypeUsed eq "otp" or ...)

Terms are `<field> <op> "<value>"` joined by and/or with optional
parentheses and `not`. Operators: eq (equals), ne (not equal), co
(contains), sw/ew (starts/ends with), gt/lt/ge/le (numeric), pr
(present -- field only), in (list of quoted values in `(...)` or
`[...]`). String literals use `\\"` / `\\\\` escapes.

The expression is tokenized before terms are read (2026-08-30 review):
a string literal is one token, so nothing inside a value -- placeholder
words, escaped quotes, operator look-alikes -- can surface as a field
or split a term. `not` applies to the next term, or to every term of
the parenthesised group that follows it; nested groups XOR.

Values for co/sw/ew are match PATTERNS: they stay on the observable
like any other value but never reach the api_actions surface, which
holds exact event types only (`eventType co "user.authentication"` is
a prefix, not an action anyone can look up).

Okta rules that ship a Splunk variant instead (`language: spl`) route
to the SPL extractor via `extract_okta_fields`. Every Okta detection
reads the one System Log stream, so `okta_system_log` is recorded as
the source table for parity with the facet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.field_extractor import (
    ExtractedFields,
    ExtractedObservable,
    _classify_field,
    _deduplicate_all,
    _route_domain_fields,
    extract_splunk_fields,
)

_SOURCE_TABLE = "okta_system_log"

_OPS = frozenset({"eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le", "pr", "in"})
# Operators whose value is a match pattern rather than an exact value.
_PATTERN_OPS = frozenset({"co", "sw", "ew"})
# Operators whose value is asserted exactly (may reach api_actions).
_EXACT_OPS = frozenset({"eq", "in"})
_CONNECTORS = frozenset({"and", "or"})
_RESERVED = _OPS | _CONNECTORS | {"not"}

# One token per string literal (escape-aware), identifier, bracket or
# comma; anything else is a single throwaway character.
_TOKEN_RE = re.compile(
    r'(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<ident>[A-Za-z_][\w.]*)"
    r"|(?P<punct>[()\[\],])"
    r"|(?P<other>\S)"
)
_ESCAPE_RE = re.compile(r"\\(.)")
_LIST_CLOSER = {"(": ")", "[": "]"}


@dataclass
class _Term:
    field: str
    op: str
    values: list[str]
    negated: bool


def _tokenize(text: str) -> list[tuple[str, str]]:
    return [(m.lastgroup or "other", m.group()) for m in _TOKEN_RE.finditer(text)]


def _unescape(literal: str) -> str:
    """Strip the surrounding quotes and resolve backslash escapes."""
    return _ESCAPE_RE.sub(r"\1", literal[1:-1])


def _parse_terms(tokens: list[tuple[str, str]]) -> tuple[list[_Term], int]:
    """Walk the token stream, returning the terms and the connector count.

    Negation is tracked two ways: `pending_not` for a `not` that applies
    to the next term, and `group_neg` (a stack of flags, one per open
    parenthesis) for `not ( ... )` groups. A term is negated when the
    XOR of its own `not`, the enclosing group flags and an `ne`
    operator is true, so `not (x ne "y")` comes out positive.
    """
    terms: list[_Term] = []
    group_neg: list[bool] = []
    pending_not = False
    connectors = 0
    n = len(tokens)
    i = 0
    while i < n:
        kind, text = tokens[i]
        if kind == "punct":
            if text == "(":
                group_neg.append(pending_not)
                pending_not = False
            elif text == ")" and group_neg:
                group_neg.pop()
            i += 1
            continue
        if kind != "ident":
            i += 1  # stray literal / character outside a term
            continue

        low = text.lower()
        if low == "not":
            pending_not = not pending_not
            i += 1
            continue
        if low in _CONNECTORS:
            connectors += 1
            pending_not = False
            i += 1
            continue
        if low in _RESERVED:
            i += 1  # operator with no field in front of it
            continue

        # A field is an identifier immediately followed by an operator.
        if not (i + 1 < n and tokens[i + 1][0] == "ident" and tokens[i + 1][1].lower() in _OPS):
            pending_not = False
            i += 1
            continue
        op = tokens[i + 1][1].lower()
        j = i + 2
        values: list[str] = []
        if op == "in":
            if j < n and tokens[j][0] == "punct" and tokens[j][1] in _LIST_CLOSER:
                closer = _LIST_CLOSER[tokens[j][1]]
                j += 1
                while j < n and not (tokens[j][0] == "punct" and tokens[j][1] == closer):
                    if tokens[j][0] == "str":
                        values.append(_unescape(tokens[j][1]))
                    j += 1
                if j < n:
                    j += 1  # consume the closer
        elif op != "pr" and j < n and tokens[j][0] == "str":
            values.append(_unescape(tokens[j][1]))
            j += 1

        negated = pending_not ^ (sum(group_neg) % 2 == 1) ^ (op == "ne")
        pending_not = False
        terms.append(_Term(field=text, op=op, values=values, negated=negated))
        i = j
    return terms, connectors


def extract_oie_fields(expression: str) -> ExtractedFields:
    """Extract observables from an Okta System Log filter expression."""
    result = ExtractedFields()
    if not expression or not isinstance(expression, str):
        return result

    terms, connectors = _parse_terms(_tokenize(expression.strip()))
    if not terms:
        return result

    result.source_tables.append(_SOURCE_TABLE)
    result.query_complexity = (
        "complex" if connectors > 6 else "moderate" if connectors > 2 else "simple"
    )

    pattern_values: set[str] = set()
    exact_values: set[str] = set()
    for term in terms:
        result.fields_used.append(term.field)
        values = [v for v in term.values if v]
        if not values:
            continue  # presence check / bare comparison: field reference only
        if not term.negated:
            if term.op in _PATTERN_OPS:
                pattern_values.update(values)
            elif term.op in _EXACT_OPS:
                exact_values.update(values)
        obs_type, obs_subtype = _classify_field(term.field)
        result.observables.append(
            ExtractedObservable(
                field=term.field, values=list(values), type=obs_type,
                subtype=obs_subtype, negated=term.negated,
            )
        )
        if obs_type == "network":
            result.network_indicators.extend(v for v in values if not re.search(r"\s", v))
        _route_domain_fields(obs_type, obs_subtype, values, term.negated, result)

    _deduplicate_all(result)
    # _deduplicate_all lifts namespaced eventType values onto api_actions
    # regardless of operator; a contains / prefix / suffix pattern is not
    # an action unless the same value is also asserted exactly.
    result.api_actions = [
        a for a in result.api_actions if a not in pattern_values or a in exact_values
    ]
    return result


def extract_okta_fields(query: str, language: str | None) -> ExtractedFields:
    """Dispatch on the detection's primary language."""
    if (language or "").lower() == "spl":
        return extract_splunk_fields(query)
    return extract_oie_fields(query)
