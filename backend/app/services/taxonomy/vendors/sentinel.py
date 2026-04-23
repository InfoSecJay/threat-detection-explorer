"""Microsoft Sentinel resolver.

Sentinel analytics rules embed telemetry signals in five places; we
walk them in precedence order. Higher tiers contribute authoritatively
for event_type (and override lower tiers); platforms and data_sources
union across all tiers.

Tier 1 — KQL query table name (authoritative)
    Every Sentinel rule begins with a table reference:
      AuditLogs | where ...
      AWSCloudTrail | where ...
      CommonSecurityLog | where DeviceVendor == "Acronis"
    The table name IS the data source. Custom tables ending in `_CL`
    get the `siem_alert` fallback.

Tier 2 — `requiredDataConnectors[].connectorId`
    Declared by the rule author. Many rules leave this empty, so it
    can't be the primary signal — but when present it's accurate.

Tier 3 — `requiredDataConnectors[].dataTypes[]`
    Overrides for specific table names (SecurityAlert can come from
    multiple connectors; dataType pins which). Includes the `_cl`
    pattern fallback for custom-log vendor tables.

Tier 4 — `Solutions/<vendor>/` folder name
    The file path is a vendor signal: `Solutions/Acronis Cyber Protect
    Cloud/...` is Acronis. Fallback when table + connector didn't
    resolve (typical for older rules that skip requiredDataConnectors).

Tier 5 — `entityMappings[].entityType`
    Last-resort event_type hint. `MailMessage` → email_message,
    `Process` → process_creation, etc. Never authoritative.
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
    authoritative_ets: set[str] = set()
    capability_ets: set[str] = set()

    table_map = _MAPPING.get("kql_tables") or {}
    connector_map = _MAPPING.get("connectors") or {}
    data_type_map = _MAPPING.get("data_types") or {}
    folder_map = _MAPPING.get("solution_folders") or {}
    entity_map = _MAPPING.get("entity_types") or {}

    # ── Tier 1: KQL table names (authoritative event_type) ──
    tables = extra.get("kql_tables") or []
    matched_any_table = False
    for tbl in tables:
        if not isinstance(tbl, str):
            continue
        key = tbl.lower().strip()
        entry = table_map.get(key)
        if entry is None and key.endswith("_cl"):
            # Vendor custom log — use the `_cl` fallback bucket.
            entry = table_map.get("*_cl")
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            authoritative_ets.update(entry.get("event_types") or [])
            matched_any_table = True

    # ── Tier 2 + 3: connectors + dataTypes (existing behavior) ──
    connectors = extra.get("requiredDataConnectors") or []
    if isinstance(connectors, dict):
        connectors = [connectors]

    for conn in connectors:
        if not isinstance(conn, dict):
            continue
        connector_id = (conn.get("connectorId") or "").lower().strip()
        data_types = conn.get("dataTypes") or []

        entry = connector_map.get(connector_id)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            # connector event_types are capability-level unless Tier 1
            # didn't match (tier 1 wins when both present).
            if matched_any_table:
                capability_ets.update(entry.get("event_types") or [])
            else:
                authoritative_ets.update(entry.get("event_types") or [])

        for dt in data_types:
            if not isinstance(dt, str):
                continue
            dtk = dt.lower().strip()
            dt_entry = data_type_map.get(dtk)
            if dt_entry:
                platforms.update(dt_entry.get("platforms") or [])
                data_sources.update(dt_entry.get("data_sources") or [])
                if matched_any_table:
                    capability_ets.update(dt_entry.get("event_types") or [])
                else:
                    authoritative_ets.update(dt_entry.get("event_types") or [])
            elif dtk.endswith("_cl"):
                # Third-party custom log bucket.
                platforms.add("cross_platform")
                data_sources.add("siem_alert")
                capability_ets.add("audit_event")

    # ── Tier 4: Solutions folder vendor mapping ──
    folder = (extra.get("solution_folder") or "").strip()
    if folder:
        entry = folder_map.get(folder.lower())
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            capability_ets.update(entry.get("event_types") or [])

    # ── Tier 5: entityMappings entityType (last-resort hint) ──
    entity_types = extra.get("entity_types") or []
    for et in entity_types:
        if not isinstance(et, str):
            continue
        entry = entity_map.get(et.lower())
        if not entry:
            continue
        # Entities NEVER set platforms/data_sources (they describe what
        # the rule returns, not where data comes from). They contribute
        # event_type hints only when nothing else did.
        if not authoritative_ets and not capability_ets:
            capability_ets.update(entry.get("event_types") or [])

    # Always includes — lightweight backfill for rules that literally
    # have nothing else to say. Kept for parity with the previous
    # resolver; leave empty unless the YAML defines something.
    always = _MAPPING.get("always_includes") or {}
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    capability_ets.update(always.get("event_types") or [])

    event_types = authoritative_ets if authoritative_ets else capability_ets

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
