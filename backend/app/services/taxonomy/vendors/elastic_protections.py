"""Elastic Protections (behavior rules / EDR artifacts) resolver.

These rules are agent-resident — they don't reference an index pattern
because they execute locally on Elastic Defend. So the data source is
ALWAYS `elastic_defend`. Platforms come from the `os_list` field. Event
type is parsed from the EQL query head (`process where ...` →
process_creation, `network where ...` → network_connection, etc.).
"""

import re
from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("elastic_protections")

# Match the EQL "category" keyword at the start of the query, e.g.
# `process where ...` or `network where ...` or `file where ...`.
_EQL_HEAD = re.compile(r"^\s*([a-z_]+)\s+where\b", re.IGNORECASE)


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Elastic Protections rule."""
    extra = parsed.extra or {}
    log_source = parsed.log_source or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    # Platforms come from os_list (or the file path, which the parser
    # stuffed into log_source.product as a backup)
    os_list = extra.get("os_list") or []
    if isinstance(os_list, str):
        os_list = [os_list]
    if not os_list and log_source.get("product"):
        os_list = [log_source.get("product")]

    os_map = _MAPPING.get("os_to_platforms") or {}
    for os_name in os_list:
        if not isinstance(os_name, str):
            continue
        canonical = os_map.get(os_name.lower().strip())
        if canonical:
            if isinstance(canonical, list):
                platforms.update(canonical)
            else:
                platforms.add(canonical)

    # Event type from EQL query head
    raw_query = parsed.detection_logic_raw
    if isinstance(raw_query, str):
        match = _EQL_HEAD.match(raw_query)
        if match:
            eql_category = match.group(1).lower()
            event_type_map = _MAPPING.get("eql_category_to_event_types") or {}
            mapped = event_type_map.get(eql_category)
            if mapped:
                if isinstance(mapped, list):
                    event_types.update(mapped)
                else:
                    event_types.add(mapped)

    # Data source: always Elastic Defend (agent-resident)
    always = _MAPPING.get("always_includes") or {}
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    event_types.update(always.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
