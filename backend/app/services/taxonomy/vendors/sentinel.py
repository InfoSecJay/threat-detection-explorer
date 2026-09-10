"""Microsoft Sentinel resolver.

Sentinel analytics rules embed telemetry signals in five places. The
query is the truth and the other tiers refine it or fall back; nothing
is unioned blindly any more. Until #141 the resolver unioned platforms
and data sources across every tier, so a CEF rule for Acronis carried
the Cisco, Fortinet and Palo Alto sources of the `CommonSecurityLog`
entry plus the same triple again from the `CEF` connector.

Tier 1 -- KQL tables (authoritative event_type)
    `AWSCloudTrail | ...` names one vendor: the entry supplies platform,
    data source and event type. Tables shared by many vendors
    (`CommonSecurityLog`, `Syslog`, `SecurityAlert`, `SecurityIncident`,
    `AzureDiagnostics`, `WindowsEvent`, `Event`) are marked
    `generic: true` in the mapping: they supply the event type and a
    generic fallback source only, never a vendor. Custom `_CL` tables
    not listed take the `*_cl` catch-all (generic, `siem_alert`).

Tier 1b -- query discriminators (the vendor of a generic table)
    `CommonSecurityLog | where DeviceVendor == "Acronis"`,
    `SecurityAlert | where ProviderName == "IoTSecurity"`,
    `WindowsEvent | where Provider == "Microsoft-Windows-Sysmon"`.
    The parser lifts these filters into `extra["kql_filters"]`; the
    `discriminators` section of the mapping turns them into the real
    platform / data source. A match refines the generic table it
    belongs to (`tables:` on the field), so `Category` on AuditLogs is
    never read as an AzureDiagnostics category.

Tier 4 (early) -- `Solutions/<vendor>/` folder
    Names the vendor of a generic table that no discriminator refined:
    a CEF rule in `Solutions/Acronis Cyber Protect Cloud` with no
    DeviceVendor filter is still Acronis. A generic table with neither
    keeps its generic fallback (CEF -> network_traffic_logs).

Tier 2 + 3 -- `requiredDataConnectors[].connectorId` / `dataTypes[]`
    The author's declaration. Platform / data source only when no
    table resolved at all (rules built on custom functions or ASIM
    parsers); otherwise they add event-type capability. Generic
    connectors (`CEF`, `Syslog`, `CustomLogsAma`) never assert a vendor
    and are the last fallback.

Tier 4 (late) -- folder fallback when nothing above resolved a source.

Tier 5 -- `entityMappings[].entityType`: last-resort event_type hint.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("sentinel")


def _apply(entry: dict, platforms: set[str], data_sources: set[str]) -> None:
    platforms.update(entry.get("platforms") or [])
    data_sources.update(entry.get("data_sources") or [])


def _match_discriminators(kql_filters: dict, disc_map: dict) -> list[tuple[str, dict]]:
    """`(field, entry)` for every query filter value that matches a
    discriminator key. Keys match case-insensitively as substrings of
    the value, longest key first, so `cisco umbrella` beats `cisco` and
    `palo alto` matches `palo alto networks`."""
    matches: list[tuple[str, dict]] = []
    for field, values in (kql_filters or {}).items():
        field_map = disc_map.get(field) or {}
        keys = sorted((k for k in field_map if k != "tables"), key=len, reverse=True)
        for value in values or []:
            if not isinstance(value, str):
                continue
            for key in keys:
                if key in value:
                    matches.append((field, field_map[key]))
                    break
    return matches


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Sentinel rule."""
    extra = parsed.extra or {}

    table_map = _MAPPING.get("kql_tables") or {}
    connector_map = _MAPPING.get("connectors") or {}
    data_type_map = _MAPPING.get("data_types") or {}
    folder_map = _MAPPING.get("solution_folders") or {}
    entity_map = _MAPPING.get("entity_types") or {}
    disc_map = _MAPPING.get("discriminators") or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    authoritative_ets: set[str] = set()
    capability_ets: set[str] = set()

    # -- Tier 1: tables --------------------------------------------------
    matched_any_table = False
    generic_tables: dict[str, dict] = {}  # table key -> entry, vendor still open
    for tbl in extra.get("kql_tables") or []:
        if not isinstance(tbl, str):
            continue
        key = tbl.lower().strip()
        entry = table_map.get(key)
        if entry is None and key.endswith("_cl"):
            entry = table_map.get("*_cl")
        if not entry:
            continue
        matched_any_table = True
        authoritative_ets.update(entry.get("event_types") or [])
        if entry.get("generic"):
            generic_tables[key] = entry
        else:
            _apply(entry, platforms, data_sources)

    # -- Tier 1b: discriminators refine the generic tables ---------------
    refined: set[str] = set()
    if generic_tables or not matched_any_table:
        for field, entry in _match_discriminators(extra.get("kql_filters") or {}, disc_map):
            owners = [o.lower() for o in ((disc_map.get(field) or {}).get("tables") or [])]
            if matched_any_table and not any(o in generic_tables for o in owners):
                continue
            _apply(entry, platforms, data_sources)
            capability_ets.update(entry.get("event_types") or [])
            refined.update(o for o in owners if o in generic_tables)

    # -- Tier 4 (early): the folder names the vendor of an unrefined
    # generic table; otherwise the table keeps its generic fallback.
    folder = (extra.get("solution_folder") or "").strip()
    folder_entry = folder_map.get(folder.lower()) if folder else None
    unrefined = [entry for key, entry in generic_tables.items() if key not in refined]
    if unrefined:
        if folder_entry and not folder_entry.get("generic"):
            _apply(folder_entry, platforms, data_sources)
            if not folder_entry.get("platforms"):
                for entry in unrefined:
                    platforms.update(entry.get("platforms") or [])
        else:
            for entry in unrefined:
                _apply(entry, platforms, data_sources)

    # -- Tier 2 + 3: connectors + dataTypes ------------------------------
    connectors = extra.get("requiredDataConnectors") or []
    if isinstance(connectors, dict):
        connectors = [connectors]
    generic_connector_entries: list[dict] = []
    for conn in connectors:
        if not isinstance(conn, dict):
            continue
        connector_id = (conn.get("connectorId") or "").lower().strip()
        entries = [connector_map.get(connector_id)]
        for dt in conn.get("dataTypes") or []:
            if not isinstance(dt, str):
                continue
            dtk = dt.lower().strip()
            dt_entry = data_type_map.get(dtk)
            if dt_entry is None and dtk.endswith("_cl"):
                dt_entry = {"data_sources": ["siem_alert"], "event_types": ["audit_event"], "generic": True}
            entries.append(dt_entry)
        for entry in entries:
            if not entry:
                continue
            (capability_ets if matched_any_table else authoritative_ets).update(entry.get("event_types") or [])
            if matched_any_table:
                continue
            if entry.get("generic"):
                generic_connector_entries.append(entry)
            else:
                _apply(entry, platforms, data_sources)

    # -- Tier 4 (late): folder, then generic connectors, when still empty
    if folder_entry:
        if not platforms and not data_sources:
            _apply(folder_entry, platforms, data_sources)
        capability_ets.update(folder_entry.get("event_types") or [])
    if not platforms and not data_sources:
        for entry in generic_connector_entries:
            _apply(entry, platforms, data_sources)

    # -- Tier 5: entity types (event_type hint only) ---------------------
    for et in extra.get("entity_types") or []:
        if not isinstance(et, str):
            continue
        entry = entity_map.get(et.lower())
        if entry and not authoritative_ets and not capability_ets:
            capability_ets.update(entry.get("event_types") or [])

    always = _MAPPING.get("always_includes") or {}
    _apply(always, platforms, data_sources)
    capability_ets.update(always.get("event_types") or [])

    event_types = authoritative_ets if authoritative_ets else capability_ets

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
