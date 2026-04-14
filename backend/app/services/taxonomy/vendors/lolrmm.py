"""LOLRMM resolver.

LOLRMM uses Sigma rule format with a `logsource` block (product/category/
service). The mapping logic is identical to Sigma's, just sourced from
`mappings/lolrmm.yaml` because LOLRMM rules are exclusively about RMM
tool detection (always Windows, mostly process_creation /
network_connection events) and the data source is "windows_security_event_log"
or "sysmon".
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("lolrmm")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed LOLRMM rule."""
    log_source = parsed.log_source or {}
    product = (log_source.get("product") or "").lower().strip()
    category = (log_source.get("category") or "").lower().strip()
    service = (log_source.get("service") or "").lower().strip()

    keys_to_try = []
    if product and service and category:
        keys_to_try.append(f"{product}/{service}/{category}")
    if product and category:
        keys_to_try.append(f"{product}/{category}")
    if product:
        keys_to_try.append(product)

    by_key = _MAPPING.get("by_key", {})
    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    for key in keys_to_try:
        entry = by_key.get(key)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])
            break  # first match wins; LOLRMM rules are simple

    # Apply the always-includes for this vendor (every LOLRMM rule pulls
    # in these defaults regardless of the specific match)
    always = _MAPPING.get("always_includes", {})
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    event_types.update(always.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
