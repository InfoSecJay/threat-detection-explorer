"""Splunk Security Content resolver.

Splunk rules carry a `data_source` list of human-readable feed names
(e.g. "Sysmon EventID 10", "ASL AWS CloudTrail", "Cisco Duo Activity").
We do prefix matching against the mapping keys (the labels are messy
and version-stamped, so exact match would miss a lot).

`tags.security_domain` (endpoint, network, identity, cloud) provides
a coarse fallback for platforms when no data_source label matches.

Event type comes from explicit Splunk metadata when present, otherwise
from search-query keyword detection (last-resort).
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("splunk")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Splunk rule."""
    extra = parsed.extra or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    # Splunk's data_source list: messy free-form labels
    raw_data_sources = extra.get("data_source") or []
    if isinstance(raw_data_sources, str):
        raw_data_sources = [raw_data_sources]

    label_map = _MAPPING.get("data_source_labels") or {}
    for label in raw_data_sources:
        if not isinstance(label, str):
            continue
        normalized = label.lower().strip()
        # Try exact match first, then prefix match
        entry = label_map.get(normalized)
        if entry is None:
            for key, mapping in label_map.items():
                if normalized.startswith(key) or key in normalized:
                    entry = mapping
                    break
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Coarse fallback: tags.security_domain
    security_domain = (extra.get("security_domain") or "").lower().strip()
    domain_map = _MAPPING.get("security_domain") or {}
    if security_domain:
        entry = domain_map.get(security_domain)
        if entry:
            platforms.update(entry.get("platforms") or [])
            # Don't override data_sources here — domain is too coarse to
            # produce a meaningful data_source.
            event_types.update(entry.get("event_types") or [])

    # Search query keyword fallback for event_type when nothing else fired
    if not event_types:
        search_text = ""
        detection_logic = parsed.detection_logic_raw
        if isinstance(detection_logic, dict):
            search_text = (detection_logic.get("search") or "").lower()
        elif isinstance(detection_logic, str):
            search_text = detection_logic.lower()

        keyword_map = _MAPPING.get("search_keywords") or {}
        for keyword, mapping in keyword_map.items():
            if keyword in search_text:
                event_types.update(mapping.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
