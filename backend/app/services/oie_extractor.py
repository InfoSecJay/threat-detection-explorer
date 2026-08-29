"""Okta System Log filter (OIE expression) extractor (issue #6 tail).

Okta customer detections carry a System Log search expression:

    eventType eq "user.risk.detect" and debugContext.debugData.risk co "level=HIGH"
    outcome.result ne "SUCCESS"
    client.ipAddress sw "10."

Terms are `<field> <op> "<value>"` joined by and/or with optional
parentheses and `not`. Operators: eq (equals), ne (not equal), co
(contains), sw/ew (starts/ends with), gt/lt/ge/le (numeric), pr
(present -- field only). Values for co/sw/ew are match PATTERNS and
are kept on the observable like any other value.

Okta rules that ship a Splunk variant instead (`language: spl`) route
to the SPL extractor via `extract_okta_fields`. Every Okta detection
reads the one System Log stream, so `okta_system_log` is recorded as
the source table for parity with the facet.
"""

from __future__ import annotations

import re

from app.services.field_extractor import (
    ExtractedFields,
    ExtractedObservable,
    _classify_field,
    _deduplicate_all,
    _route_domain_fields,
    extract_splunk_fields,
)

_TERM_RE = re.compile(
    r'(?P<neg>\bnot\s+)?(?P<field>[A-Za-z_][\w.]*)\s+(?P<op>eq|ne|co|sw|ew|gt|lt|ge|le|pr)\b'
    r'(?:\s*"(?P<val>[^"]*)")?',
    re.IGNORECASE,
)
_SOURCE_TABLE = "okta_system_log"


def extract_oie_fields(expression: str) -> ExtractedFields:
    """Extract observables from an Okta System Log filter expression."""
    result = ExtractedFields()
    if not expression or not isinstance(expression, str):
        return result

    text = expression.strip()
    terms = list(_TERM_RE.finditer(text))
    if not terms:
        return result

    result.source_tables.append(_SOURCE_TABLE)
    connectors = len(re.findall(r"\b(?:and|or)\b", text, re.IGNORECASE))
    result.query_complexity = (
        "complex" if connectors > 6 else "moderate" if connectors > 2 else "simple"
    )

    for m in terms:
        field_name = m.group("field")
        op = m.group("op").lower()
        value = m.group("val")
        negated = bool(m.group("neg")) or op == "ne"
        result.fields_used.append(field_name)
        if op == "pr" or value is None or value == "":
            continue  # presence check / bare comparison: field reference only
        obs_type, obs_subtype = _classify_field(field_name)
        result.observables.append(
            ExtractedObservable(
                field=field_name, values=[value], type=obs_type,
                subtype=obs_subtype, negated=negated,
            )
        )
        if obs_type == "network" and not re.search(r"\s", value):
            result.network_indicators.append(value)
        _route_domain_fields(obs_type, obs_subtype, [value], negated, result)

    _deduplicate_all(result)
    return result


def extract_okta_fields(query: str, language: str | None) -> ExtractedFields:
    """Dispatch on the detection's primary language."""
    if (language or "").lower() == "spl":
        return extract_splunk_fields(query)
    return extract_oie_fields(query)
