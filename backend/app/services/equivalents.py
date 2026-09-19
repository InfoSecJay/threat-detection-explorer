"""Nightly "same behaviour elsewhere" pass (DX-07 / #149).

For every rule: which sources hold a rule keying on the same thing?
The per-rule related panel (services/related.py) answers that for one
rule at request time; a facet over the whole corpus cannot run that
per row, so this batch writes the answer into
Detection.equivalent_sources at the end of every sync and the "has
equivalent in" facet (and the `equiv:` query field) become plain list
filters.

Qualifying bar, stricter than the panel's "shares one observable" so a
rule that merely mentions powershell.exe does not gain an equivalent
in every source: two rules are equivalent when they share at least one
observable on a qualifying surface (process name, registry key, API
action, path, indicator, event ID; never a bare source table) AND
either share an ATT&CK technique or share a second observable.

Computed in memory from one column scan. An inverted index per
observable value makes the pass linear in the number of postings; a
value carried by more than GENERIC_SHARE of the corpus is too generic
to pair two rules on its own (it still counts as a shared observable
once a rarer value paired them). Deprecated rules neither give nor get
an equivalent (#109: retired content pads nothing).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Iterable

from sqlalchemy import bindparam, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection

logger = logging.getLogger(__name__)

# related.py's qualifying surfaces, in the order the batch reads them.
SURFACES = (
    "extracted_process_names",
    "extracted_registry_keys",
    "extracted_api_actions",
    "extracted_file_paths",
    "extracted_network_indicators",
    "extracted_event_ids",
)
GENERIC_SHARE = 0.01
GENERIC_MIN = 50
_WRITE_CHUNK = 1000


def _values(raw) -> set[str]:
    return {v.strip().lower() for v in (raw or []) if isinstance(v, str) and v.strip()}


def compute_equivalent_sources(
    rows: Iterable[tuple],
    *,
    generic_min: int = GENERIC_MIN,
    generic_share: float = GENERIC_SHARE,
) -> dict[str, list[str]]:
    """{rule id: sorted sources with a same-behaviour rule}.

    `rows` are (id, source, status, mitre_techniques, *surface lists in
    SURFACES order). Deprecated rows are skipped entirely, so they are
    absent from the result (the writer stores [] for them).
    """
    ids: list[str] = []
    sources: list[str] = []
    techs: list[set[str]] = []
    obs: list[set[str]] = []
    for row in rows:
        rid, source, status, mitre_techniques, *surfaces = row
        if status == "deprecated":
            continue
        ids.append(rid)
        sources.append(source)
        techs.append({t.upper() for t in (mitre_techniques or []) if isinstance(t, str) and t})
        values: set[str] = set()
        for name, raw in zip(SURFACES, surfaces):
            values.update(f"{name}:{v}" for v in _values(raw))
        obs.append(values)

    postings: dict[str, list[int]] = defaultdict(list)
    for i, values in enumerate(obs):
        for v in values:
            postings[v].append(i)
    cap = max(generic_min, int(len(ids) * generic_share))
    distinctive = {v: idx for v, idx in postings.items() if 1 < len(idx) <= cap}

    result: dict[str, list[str]] = {}
    for i in range(len(ids)):
        candidates: set[int] = set()
        for v in obs[i]:
            idx = distinctive.get(v)
            if idx:
                candidates.update(idx)
        candidates.discard(i)
        found: set[str] = set()
        for j in candidates:
            if sources[j] in found:
                continue
            shared = len(obs[i] & obs[j])
            if shared >= 2 or (shared >= 1 and techs[i] & techs[j]):
                found.add(sources[j])
        result[ids[i]] = sorted(found)
    return result


_COLS = (
    Detection.id, Detection.source, Detection.status, Detection.mitre_techniques,
    *[getattr(Detection, s) for s in SURFACES],
    Detection.equivalent_sources,
)


async def write_equivalent_sources(
    db: AsyncSession,
    *,
    generic_min: int = GENERIC_MIN,
    generic_share: float = GENERIC_SHARE,
) -> dict[str, int | float]:
    """Recompute every rule's equivalent_sources; write only the rows
    whose value changed. Returns counters for the sync log."""
    t0 = time.perf_counter()
    rows = (await db.execute(select(*_COLS))).all()
    current = {r[0]: sorted(v for v in (r[-1] or []) if isinstance(v, str)) for r in rows}
    computed = compute_equivalent_sources(
        (tuple(r[:-1]) for r in rows), generic_min=generic_min, generic_share=generic_share,
    )
    changes = [
        {"_id": rid, "_v": computed.get(rid, [])}
        for rid, before in current.items()
        if computed.get(rid, []) != before
    ]
    if changes:
        table = Detection.__table__
        stmt = (
            table.update()
            .where(table.c.id == bindparam("_id"))
            .values(equivalent_sources=bindparam("_v", type_=table.c.equivalent_sources.type))
        )
        for start in range(0, len(changes), _WRITE_CHUNK):
            await db.execute(stmt, changes[start:start + _WRITE_CHUNK])
        await db.commit()
    stats = {
        "rules": len(rows),
        "with_equivalent": sum(1 for v in computed.values() if v),
        "updated": len(changes),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    logger.info("equivalent sources: %s", stats)
    return stats
