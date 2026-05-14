"""Elastic Hunting resolver.

Hunting queries embed `FROM logs-*` clauses in their ES|QL queries plus
list `integration` plugins. We parse the query string for index patterns
and union with the integrations field. Hunting is broader than detection
rules, so the always_includes pulls in the `hunting_query` event type
unconditionally.
"""

import re
from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping
from app.services.taxonomy.vendors.elastic import _index_matches

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("elastic_hunting")

# Match `from logs-something*` or `FROM logs-foo.bar-*` in ES|QL queries.
_FROM_PATTERN = re.compile(r"\bfrom\s+([a-z][\w.\-*]*)", re.IGNORECASE)


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Elastic Hunting query."""
    extra = parsed.extra or {}
    log_source = parsed.log_source or {}

    integrations = extra.get("integration") or []
    if isinstance(integrations, str):
        integrations = [integrations]

    # OSQuery rules (language=["SQL"]) query OSQuery virtual tables, not
    # auditd / elastic_defend telemetry. The data_source override avoids
    # by_product["linux"] -> auditd and integrations["endpoint"] ->
    # elastic_defend, both of which mis-classify these rules.
    language_list = extra.get("language") or []
    is_osquery = any(
        isinstance(l, str) and l.upper() == "SQL" for l in language_list
    )

    # Extract `FROM <index>` patterns from the ES|QL query body
    indices: list[str] = []
    raw_query = parsed.detection_logic_raw
    if isinstance(raw_query, list):
        raw_query = "\n".join(str(q) for q in raw_query)
    if isinstance(raw_query, str):
        indices = [m.group(1) for m in _FROM_PATTERN.finditer(raw_query)]

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    # Index pattern matching (mostly inherited from Elastic main mappings,
    # but kept separately so hunting-specific patterns can be added)
    index_map = _MAPPING.get("index_patterns") or {}
    for idx in indices:
        idx_lower = idx.lower().strip()
        entry = None
        if idx_lower in index_map:
            entry = index_map[idx_lower]
        else:
            for pattern, mapping in index_map.items():
                if _index_matches(idx_lower, pattern.lower()):
                    entry = mapping
                    break
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Integration list (e.g. ["aws.cloudtrail"], ["endpoint", "windows"])
    integration_map = _MAPPING.get("integrations") or {}
    for integ in integrations:
        if not isinstance(integ, str):
            continue
        entry = integration_map.get(integ.lower().strip())
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # `product` field on the parsed log_source (set by the Elastic Hunting
    # parser based on file path — windows/, linux/, aws/, etc.)
    product = (log_source.get("product") or "").lower().strip()
    product_map = _MAPPING.get("by_product") or {}
    if product:
        entry = product_map.get(product)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Always includes (every hunting query is a `hunting_query` event type)
    always = _MAPPING.get("always_includes") or {}
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    event_types.update(always.get("event_types") or [])

    # OSQuery override: replace data_sources with the single `osquery`
    # value -- the by_product / integrations mappings above pull in
    # auditd / elastic_defend which mis-describe OSQuery hunts.
    if is_osquery:
        data_sources = {"osquery"}

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
