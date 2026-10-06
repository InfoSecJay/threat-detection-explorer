"""Nightly duplicate-pair pass (DX-10 / #166).

PyPanther (panther-labs/pypanther) is panther-analysis generated into
Python rule classes: the same detections, shipped twice. Both repos are
tracked, so until this pass every pair counted twice in technique
coverage, in the actor scores and in the equivalence facet, with no
link between the two rule pages.

Pairing key: every pypanther rule id is the Panther RuleID plus
"-prototype" (595 of 595 on 2026-10-06; titles differ on 8 of them, so
titles are not the key). The pass writes the canonical twin's id into
Detection.duplicate_of on the port row, clears a link whose twin is
gone, and never touches rows of non-port sources. What a link means for
the numbers lives in services/coverage_scope.py (PORT_SOURCES and
duplicate_conditions); the catalog and search still list both rows.
"""

from __future__ import annotations

import logging
import time
from typing import Iterable, Optional

from sqlalchemy import bindparam, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.coverage_scope import PORT_SOURCES
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

# port source -> suffix its rule ids carry on top of the canonical id.
PORT_ID_SUFFIXES: dict[str, str] = {"pypanther": "-prototype"}
_WRITE_CHUNK = 1000


def canonical_rule_id(source: str, rule_id: Optional[str]) -> Optional[str]:
    """The canonical repository's rule id a port row points at, or None
    when ``source`` is not a port or the id does not carry the suffix."""
    suffix = PORT_ID_SUFFIXES.get(source)
    if not suffix or not rule_id or not rule_id.endswith(suffix):
        return None
    stem = rule_id[: -len(suffix)]
    return stem or None


def compute_duplicate_links(rows: Iterable[tuple]) -> dict[str, Optional[str]]:
    """{port row id: canonical row id or None} for every row of a port
    source. ``rows`` are (id, source, rule_id). Canonical rows are looked
    up by (canonical source, rule_id); a canonical rule id carried by
    more than one row pairs nothing, because picking one silently would
    hide a real upstream problem."""
    rows = list(rows)
    canonical: dict[tuple[str, str], list[str]] = {}
    for rid, source, rule_id in rows:
        if source in PORT_SOURCES.values() and rule_id:
            canonical.setdefault((source, rule_id), []).append(rid)
    links: dict[str, Optional[str]] = {}
    for rid, source, rule_id in rows:
        if source not in PORT_SOURCES:
            continue
        target = canonical_rule_id(source, rule_id)
        hits = canonical.get((PORT_SOURCES[source], target), []) if target else []
        links[rid] = hits[0] if len(hits) == 1 else None
    return links


async def write_duplicate_links(db: AsyncSession) -> dict[str, int | float]:
    """Recompute duplicate_of for every port-source row; write only the
    rows whose value changed. Returns counters for the sync log."""
    t0 = time.perf_counter()
    rows = (
        await db.execute(
            select(Detection.id, Detection.source, Detection.rule_id, Detection.duplicate_of)
        )
    ).all()
    current = {r[0]: r[3] for r in rows if r[1] in PORT_SOURCES}
    computed = compute_duplicate_links((r[0], r[1], r[2]) for r in rows)
    changes = [
        {"_id": rid, "_v": computed.get(rid)}
        for rid, before in current.items()
        if computed.get(rid) != before
    ]
    if changes:
        table = Detection.__table__
        # Touch updated_at on the rows whose link changed: the corpus
        # caches (statistics, actor bundle, heatmaps) key on
        # (count, max(updated_at)), so an aggregate computed in the gap
        # between the sync finishing and this pass cannot outlive it.
        stmt = (
            table.update()
            .where(table.c.id == bindparam("_id"))
            .values(
                duplicate_of=bindparam("_v", type_=table.c.duplicate_of.type),
                updated_at=utcnow(),
            )
        )
        for start in range(0, len(changes), _WRITE_CHUNK):
            await db.execute(stmt, changes[start:start + _WRITE_CHUNK])
        await db.commit()
    stats = {
        "ports": len(current),
        "linked": sum(1 for v in computed.values() if v),
        "unlinked": sum(1 for v in computed.values() if not v),
        "updated": len(changes),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    logger.info("duplicate links: %s", stats)
    return stats
