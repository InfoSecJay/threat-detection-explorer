"""GitLab TLDR resolver.

Keyed on the Sigma `logsource.service` (the GitLab log file or
component). A correlation document has no logsource of its own; the
parser hands over the services of the base rules it counts in
`log_source["services"]`, and the result is their union.

A service missing from `mappings/gitlab.yaml` resolves to the GitLab
platform with no data source, which the drift report surfaces.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("gitlab")


def services_of(parsed: "ParsedRule") -> list[str]:
    """Lower-cased logsource services of a parsed GitLab rule."""
    log_source = parsed.log_source or {}
    services = log_source.get("services") or []
    if not services and log_source.get("service"):
        services = [log_source["service"]]
    return [str(s).strip().lower() for s in services if s and str(s).strip()]


def resolve(parsed: "ParsedRule") -> dict:
    by_service = _MAPPING.get("by_service") or {}
    default = _MAPPING.get("default") or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()
    for service in services_of(parsed):
        entry = by_service.get(service)
        if not entry:
            continue
        platforms.update(entry.get("platforms") or [])
        data_sources.update(entry.get("data_sources") or [])
        event_types.update(entry.get("event_types") or [])

    if not platforms:
        platforms.update(default.get("platforms") or [])
    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
