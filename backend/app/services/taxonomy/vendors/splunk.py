"""Splunk Security Content resolver.

Splunk rules don't have a clean index-pattern field like Elastic. The
telemetry source has to be inferred from several places in a tiered
way — the earlier tiers are more precise and should override later
tiers when they disagree on event_type.

## Tier 1 — Datamodels (authoritative event_type)

Rules that `tstats ... from datamodel=Endpoint.Processes` OR use the
shorthand `| from datamodel Endpoint.Processes` are explicitly naming
the telemetry category. The datamodel IS the event type. This is the
most precise signal we have — a `datamodel=Endpoint.Processes` rule is
looking at process_creation events regardless of which underlying feed
(Sysmon 1 / Windows 4688 / CrowdStrike / etc.) actually populates the
datamodel.

## Tier 2 — Macros (backtick-wrapped shortcuts)

Splunk rules reference feeds via macros like `sysmon`, `powershell`,
`okta`, `cloudtrail`. Some macros are authoritative for event_type
(`okta` is always authentication; `cloudtrail` is always api_call);
others are generic (bare `sysmon` covers every EventCode). The YAML
entry flags this via `authoritative: true/false`.

## Tier 3 — Structured `data_source` field labels

Splunk's `tags.data_source` array lists the feeds the rule queries
(e.g., "Sysmon EventID 1", "ASL AWS CloudTrail"). These contribute
platforms + data_sources freely; they're a LAST resort for event_types
because a coarse feed (Windows Security Event Log) can produce many
different event types and we shouldn't preemptively claim all of them.

## Tier 4 — `tags.security_domain`

Coarse fallback (endpoint / network / identity / cloud). Fills any
dimension still empty after higher tiers.

## Tier 5 — Search-text keywords

Last-resort substring match on the search query. Catches rules that
skip macros and write raw SPL like `index=main sourcetype=xmlwineventlog
EventCode=4688`. Fills gaps only.
"""

import re
from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("splunk")


# `datamodel=Endpoint.Processes` OR `from datamodel Endpoint.Processes`
# (Splunk supports both forms). Case-insensitive; normalize to lowercase
# and strip quotes. The captured group is the `Root.Node` reference.
_DATAMODEL_PATTERNS = [
    re.compile(r"datamodel\s*=\s*([A-Za-z_][\w.]*)", re.IGNORECASE),
    re.compile(r"\bfrom\s+datamodel\s+([A-Za-z_][\w.]*)", re.IGNORECASE),
]

# Backtick-wrapped macro references. Splunk syntax supports macro
# arguments (`macro_name(arg1, arg2)`) — we ignore the args and match on
# the bare name.
_MACRO_PATTERN = re.compile(r"`([a-z_][a-z0-9_]*)(?:\s*\([^`]*\))?`", re.IGNORECASE)


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy for a parsed Splunk rule using the
    tiered model documented at the top of the module."""
    extra = parsed.extra or {}

    search_text = _get_search_text(parsed)

    platforms: set[str] = set()
    data_sources: set[str] = set()
    # Keep authoritative and capability event_type contributions separate
    # until the end so higher tiers can override lower ones.
    authoritative_ets: set[str] = set()
    capability_ets: set[str] = set()

    datamodel_map = _MAPPING.get("datamodels") or {}
    macro_map = _MAPPING.get("macros") or {}
    label_map = _MAPPING.get("data_source_labels") or {}
    domain_map = _MAPPING.get("security_domain") or {}
    keyword_map = _MAPPING.get("search_keywords") or {}

    # ── Tier 1: Datamodels ──
    for dm in _extract_datamodels(search_text):
        entry = datamodel_map.get(dm)
        if entry is None and "." in dm:
            # Try the top-level root (e.g. `web.web` → `web`)
            entry = datamodel_map.get(dm.split(".", 1)[0])
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            authoritative_ets.update(entry.get("event_types") or [])

    # ── Tier 2: Macros ──
    for macro_name in _extract_macros(search_text):
        entry = macro_map.get(macro_name)
        if not entry:
            continue
        platforms.update(entry.get("platforms") or [])
        data_sources.update(entry.get("data_sources") or [])
        ets = entry.get("event_types") or []
        if entry.get("authoritative"):
            authoritative_ets.update(ets)
        else:
            capability_ets.update(ets)

    # ── Tier 3: data_source field labels ──
    raw_data_sources = extra.get("data_source") or []
    if isinstance(raw_data_sources, str):
        raw_data_sources = [raw_data_sources]
    for label in raw_data_sources:
        if not isinstance(label, str):
            continue
        normalized = label.lower().strip()
        entry = label_map.get(normalized)
        if entry is None:
            for key, mapping in label_map.items():
                if normalized.startswith(key) or key in normalized:
                    entry = mapping
                    break
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            # data_source labels are capability-level for event_types —
            # a coarse feed like "Windows Security Event Log" can produce
            # dozens of event codes; letting it preempt a datamodel's
            # authoritative event_type caused the 4-event_type explosion
            # we saw on `tstats datamodel=Endpoint.Processes` rules.
            capability_ets.update(entry.get("event_types") or [])

    # ── Tier 4: security_domain (platforms + event_type gap-fill) ──
    security_domain = (extra.get("security_domain") or "").lower().strip()
    if security_domain:
        entry = domain_map.get(security_domain)
        if entry:
            if not platforms:
                platforms.update(entry.get("platforms") or [])
            # capability only — domain is coarser than a datamodel
            capability_ets.update(entry.get("event_types") or [])

    # ── Tier 5: search-text keyword substrings ──
    if not (platforms and data_sources and (authoritative_ets or capability_ets)):
        for keyword, mapping in keyword_map.items():
            if keyword not in search_text:
                continue
            if not platforms:
                platforms.update(mapping.get("platforms") or [])
            if not data_sources:
                data_sources.update(mapping.get("data_sources") or [])
            capability_ets.update(mapping.get("event_types") or [])

    # Event_type resolution: authoritative wins. If nothing authoritative
    # matched, fall back to the capability union.
    event_types = authoritative_ets if authoritative_ets else capability_ets

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }


def _get_search_text(parsed: "ParsedRule") -> str:
    dl = parsed.detection_logic_raw
    if isinstance(dl, dict):
        return (dl.get("search") or "").lower()
    if isinstance(dl, str):
        return dl.lower()
    return ""


def _extract_datamodels(search_text: str) -> list[str]:
    """Return lowercased datamodel references found in the search text."""
    found: list[str] = []
    for pattern in _DATAMODEL_PATTERNS:
        for match in pattern.finditer(search_text):
            name = match.group(1).strip().lower()
            if name and name not in found:
                found.append(name)
    return found


def _extract_macros(search_text: str) -> list[str]:
    """Return lowercased macro names found in backtick references."""
    found: list[str] = []
    for match in _MACRO_PATTERN.finditer(search_text):
        name = match.group(1).strip().lower()
        if name and name not in found:
            found.append(name)
    return found
