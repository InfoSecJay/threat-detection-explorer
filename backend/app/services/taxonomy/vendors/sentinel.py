"""Microsoft Sentinel resolver.

Sentinel rules carry `requiredDataConnectors`, a list of `connectorId` +
`dataTypes` pairs that explicitly declare which Log Analytics tables the
rule queries. We map each (connectorId, dataType) pair to canonical
values via `mappings/sentinel.yaml`.

Some Sentinel rules join multiple tables (e.g. SecurityAlert +
CoreAzureBackup); the resolver unions across all matching connectors.

Event type for Sentinel is largely audit/api_call, but rules that join
SecurityAlert from Defender for Endpoint or AV alerts produce richer
event_types — see the connector mappings in the YAML.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("sentinel")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Sentinel rule."""
    extra = parsed.extra or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    connector_map = _MAPPING.get("connectors") or {}
    data_type_map = _MAPPING.get("data_types") or {}

    connectors = extra.get("requiredDataConnectors") or []
    if isinstance(connectors, dict):
        connectors = [connectors]

    for conn in connectors:
        if not isinstance(conn, dict):
            continue
        connector_id = (conn.get("connectorId") or "").lower().strip()
        data_types = conn.get("dataTypes") or []

        # Map by connectorId
        entry = connector_map.get(connector_id)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

        # Per-dataType overrides (e.g. SecurityAlert can mean different
        # things depending on the connector)
        for dt in data_types:
            if not isinstance(dt, str):
                continue
            entry = data_type_map.get(dt.lower().strip())
            if entry:
                platforms.update(entry.get("platforms") or [])
                data_sources.update(entry.get("data_sources") or [])
                event_types.update(entry.get("event_types") or [])

    # Always includes — every Sentinel rule produces api_call / audit_event
    # at minimum because all the underlying tables are admin/audit logs
    always = _MAPPING.get("always_includes") or {}
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    event_types.update(always.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
