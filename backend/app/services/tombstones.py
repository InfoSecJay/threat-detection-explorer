"""Record and serve tombstones for upstream-removed rules (#87 / F11)."""

from __future__ import annotations

import gzip
import json
import logging
from typing import Iterable, Optional

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.removed_detection import RemovedDetection
from app.services.corpus_snapshot import _row_to_dict

logger = logging.getLogger(__name__)


def make_tombstone(d: Detection) -> RemovedDetection:
    payload = json.dumps(_row_to_dict(d), ensure_ascii=False, sort_keys=True).encode("utf-8")
    return RemovedDetection(
        id=d.id,
        source=d.source,
        rule_id=d.rule_id,
        source_file=d.source_file,
        title=d.title,
        severity=d.severity,
        mitre_techniques=[t for t in (d.mitre_techniques or []) if isinstance(t, str)],
        first_seen_at=d.created_at,
        payload_gz=gzip.compress(payload, compresslevel=6),
    )


async def record_removed(db: AsyncSession, rows: Iterable[Detection]) -> int:
    """Preserve rows about to be deleted by the stale-rule cleanup.

    merge() so a rule that reappears and vanishes again keeps one
    tombstone (latest wins). Never raises: losing a tombstone must not
    break the sync.
    """
    n = 0
    for d in rows:
        try:
            await db.merge(make_tombstone(d))
            n += 1
        except Exception as e:  # noqa: BLE001
            logger.warning(f"tombstone failed for {d.id}: {e}")
    return n


async def get_tombstone(db: AsyncSession, identifier: str) -> Optional[dict]:
    """Tombstone payload for a removed rule, by id or upstream rule id.

    Includes the last-seen rule body and up to five live rules covering
    the same primary technique so the dead link still leads somewhere.
    """
    row = await db.get(RemovedDetection, identifier)
    if row is None:
        row = (
            await db.execute(
                select(RemovedDetection).where(RemovedDetection.rule_id == identifier).limit(1)
            )
        ).scalar_one_or_none()
    if row is None:
        return None

    last_seen = json.loads(gzip.decompress(row.payload_gz).decode("utf-8"))

    successors: list[dict] = []
    for tid in row.mitre_techniques[:1]:
        rows = (
            await db.execute(
                select(Detection.id, Detection.title, Detection.source, Detection.severity)
                .where(cast(Detection.mitre_techniques, String).ilike(f'%"{tid}"%'))
                .limit(5)
            )
        ).all()
        successors = [
            {"id": r[0], "title": r[1], "source": r[2], "severity": r[3]} for r in rows
        ]

    # A rule that came BACK after being tombstoned is not removed: the
    # caller checks the live table first, so reaching here means the id
    # is genuinely gone.
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "source": row.source,
        "source_file": row.source_file,
        "title": row.title,
        "severity": row.severity,
        "mitre_techniques": row.mitre_techniques,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "removed_at": row.removed_at.isoformat() if row.removed_at else None,
        "last_seen": last_seen,
        "successors": successors,
        "removed": True,
    }
