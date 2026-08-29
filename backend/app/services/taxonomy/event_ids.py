"""Per-event-ID taxonomy refinement (issue #16).

The vendor mapping files classify a rule by its LOGSOURCE. For coarse
channels (Sigma `windows/security`, Sentinel `SecurityEvent`, Splunk
"Windows Event Log Security 4xxx") that yields `event_types:
[audit_event]` -- accurate but useless for filtering: 4624 (logon),
4688 (process creation) and 4728 (group change) all land in the same
bucket. `docs/taxonomy.md` section 1 deliberately refused to GUESS a
finer type from the channel alone.

This module lifts that limit without guessing: when the rule's own
logic pins specific event IDs (extracted into
`extracted_event_ids`), `mappings/event_ids.yaml` says what those IDs
are and the coarse type is replaced by the dictionary's types.

Semantics of `refine_event_types` (pure function, unit-tested):
- Gated on the rule being Windows-scoped (platform or data source).
  IDs are matched by number only, so a Linux rule with `type=1` must
  never pick up the Sysmon meaning.
- Unknown IDs never change anything on their own.
- Coarse types (`audit_event`, `unknown`) are REPLACED by the mapped
  types; specific types the vendor mapping already produced
  (`process_creation`, `authentication`, ...) are KEPT and unioned.
- If at least one ID was unknown and the rule was `audit_event`, the
  `audit_event` tag stays -- part of the rule is still unclassified.

Applied once, for every source, in `NormalizedDetection.__post_init__`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from app.services.taxonomy.canonical import EVENT_TYPES

logger = logging.getLogger(__name__)

_PATH = Path(__file__).resolve().parent / "mappings" / "event_ids.yaml"

# Types the dictionary is allowed to replace. Everything else came from
# an explicit vendor category and is authoritative.
COARSE_EVENT_TYPES: frozenset[str] = frozenset({"audit_event", "unknown"})

# Data sources that prove a rule reads Windows event logs even when the
# vendor mapping did not set a platform (defensive; every Windows
# mapping sets the platform too).
WINDOWS_DATA_SOURCES: frozenset[str] = frozenset(
    {
        "sysmon",
        "windows_security_event_log",
        "windows_powershell",
        "windows_defender_event_log",
        "windows_event_logs",
    }
)


@dataclass(frozen=True)
class EventIdEntry:
    event_id: str
    provider: str
    channel: str
    label: str
    event_types: tuple[str, ...]


def _load(strict: bool = False) -> dict[str, EventIdEntry]:
    """Parse the YAML into a flat {event_id: entry} index.

    Duplicate IDs across providers and non-canonical event types are
    programming errors: with `strict=True` (tests) they raise; at
    runtime they log and the offending entry is skipped so a typo in
    the dictionary degrades to "no refinement" instead of crashing
    ingestion.
    """
    try:
        data = yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        if strict:
            raise
        logger.error("event_ids.yaml unreadable (%s); refinement disabled", exc)
        return {}

    index: dict[str, EventIdEntry] = {}
    for provider, block in (data.get("providers") or {}).items():
        channel = str((block or {}).get("channel") or provider)
        for raw_id, spec in ((block or {}).get("events") or {}).items():
            eid = str(raw_id).strip()
            spec = spec or {}
            types = tuple(str(t) for t in (spec.get("event_types") or []))
            problems = []
            if eid in index:
                problems.append(
                    f"event id {eid} defined by both {index[eid].provider} and {provider}"
                )
            bad = [t for t in types if t not in EVENT_TYPES]
            if bad:
                problems.append(f"event id {eid}: non-canonical event_types {bad}")
            if not types:
                problems.append(f"event id {eid}: no event_types")
            if problems:
                if strict:
                    raise ValueError("event_ids.yaml: " + "; ".join(problems))
                logger.warning("event_ids.yaml: %s -- entry skipped", "; ".join(problems))
                continue
            index[eid] = EventIdEntry(
                event_id=eid,
                provider=str(provider),
                channel=channel,
                label=str(spec.get("label") or ""),
                event_types=types,
            )
    return index


EVENT_ID_INDEX: dict[str, EventIdEntry] = _load()


def lookup(event_id: str | int) -> EventIdEntry | None:
    """Dictionary entry for an event ID, or None when unknown."""
    return EVENT_ID_INDEX.get(str(event_id).strip())


def is_windows_scoped(platforms: Iterable[str], data_sources: Iterable[str]) -> bool:
    return "windows" in set(platforms) or bool(set(data_sources) & WINDOWS_DATA_SOURCES)


def refine_event_types(
    event_types: Iterable[str],
    platforms: Iterable[str],
    data_sources: Iterable[str],
    event_ids: Iterable[str],
) -> list[str]:
    """Second-pass classification from the rule's own event IDs.

    Returns the (sorted) refined list, or the input unchanged when
    nothing applies. See the module docstring for the rules.
    """
    current = [t for t in event_types if isinstance(t, str)]
    ids = [str(i).strip() for i in event_ids if str(i).strip()]
    if not ids or not is_windows_scoped(platforms, data_sources):
        return list(current)

    mapped: set[str] = set()
    unknown = False
    for eid in ids:
        entry = EVENT_ID_INDEX.get(eid)
        if entry is None:
            unknown = True
            continue
        mapped.update(entry.event_types)

    if not mapped:
        return list(current)

    current_set = set(current)
    result = (current_set - COARSE_EVENT_TYPES) | mapped
    if unknown and "audit_event" in current_set:
        result.add("audit_event")
    return sorted(result)


def labels_for(event_ids: Iterable[str]) -> dict[str, str]:
    """{event_id: label} for the IDs the dictionary knows."""
    out: dict[str, str] = {}
    for eid in event_ids:
        entry = lookup(eid)
        if entry is not None:
            out[entry.event_id] = entry.label
    return out


def dictionary() -> dict[str, dict]:
    """Whole dictionary as plain JSON-able data for the API."""
    return {
        eid: {
            "label": e.label,
            "provider": e.provider,
            "channel": e.channel,
            "event_types": list(e.event_types),
        }
        for eid, e in sorted(EVENT_ID_INDEX.items(), key=lambda kv: (len(kv[0]), kv[0]))
    }
