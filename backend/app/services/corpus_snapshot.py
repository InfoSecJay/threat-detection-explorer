"""Write the nightly full-corpus snapshot (#94 / teardown S5.1).

Called by the worker at the end of every successful full sync, next to
the MITRE coverage snapshot. One row per (day, source): the source's
entire normalized corpus as gzip-compressed JSONL, so the exact state
of the corpus on any past date can be reconstructed -- the raw
material for tombstones, historical digests and quarterly coverage
reports.

Same-day re-runs overwrite (last sync of the day wins).
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import date, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.corpus_snapshot import CorpusSnapshot
from app.models.detection import Detection
from app.services.volume_guard import SNAPSHOT_CAP_SHARE, database_over_share
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

# Sync bookkeeping columns that say nothing about the rule itself.
_EXCLUDED_COLUMNS = {"sync_run_id", "created_at", "updated_at"}


def _row_to_dict(d: Detection) -> dict:
    out = {}
    for col in Detection.__table__.columns:
        if col.name in _EXCLUDED_COLUMNS:
            continue
        v = getattr(d, col.name)
        if isinstance(v, datetime):
            v = v.isoformat()
        out[col.name] = v
    return out


async def write_corpus_snapshot(db: AsyncSession, snapshot_date: date | None = None) -> dict[str, int]:
    """Snapshot every source's corpus for `snapshot_date` (default today, UTC).

    Returns {source: rule_count}. Failures raise -- the caller decides
    whether a missing snapshot fails the sync (it logs and continues:
    the corpus itself is fine, only the historical record is short one
    night, which the next night's run does not depend on).
    """
    day = snapshot_date or utcnow().date()
    counts: dict[str, int] = {}
    if await _database_over_snapshot_cap(db):
        return counts

    sources = (await db.execute(select(Detection.source).distinct())).scalars().all()
    for source in sorted(sources):
        rows = (
            await db.execute(select(Detection).where(Detection.source == source))
        ).scalars().all()
        lines = "\n".join(json.dumps(_row_to_dict(r), ensure_ascii=False, sort_keys=True) for r in rows)
        raw = lines.encode("utf-8")
        payload = gzip.compress(raw, compresslevel=6)

        await db.execute(
            delete(CorpusSnapshot).where(
                CorpusSnapshot.snapshot_date == day, CorpusSnapshot.source == source,
            )
        )
        db.add(CorpusSnapshot(
            snapshot_date=day,
            source=source,
            rule_count=len(rows),
            payload_gz=payload,
            payload_bytes=len(raw),
        ))
        counts[source] = len(rows)
        # Flush per source so memory holds one source's rows at a time.
        await db.flush()

    await db.commit()
    total = sum(counts.values())
    logger.info(
        f"Corpus snapshot {day}: {total} rules across {len(counts)} sources"
    )
    return counts


# Snapshots are the one optional, unbounded consumer of the volume
# (~16MB/night), so they stop first (see volume_guard for the rationale
# and the sync-level threshold above this one). The sync itself is
# never blocked here; only the snapshot.


async def _database_over_snapshot_cap(db: AsyncSession) -> bool:
    over = await database_over_share(db, SNAPSHOT_CAP_SHARE)
    if over is None:
        return False
    size, _cap = over
    logger.error(
        f"Corpus snapshot SKIPPED: database is {size / 1_048_576:.0f}MB, over "
        f"{SNAPSHOT_CAP_SHARE:.0%} of the {settings.postgres_volume_mb}MB volume "
        f"(POSTGRES_VOLUME_MB). Grow the Railway volume and set POSTGRES_VOLUME_MB "
        f"to resume nightly snapshots; the historical record is short this night."
    )
    return True


async def read_corpus_snapshot(db: AsyncSession, snapshot_date: date, source: str) -> list[dict]:
    """Load one (day, source) snapshot back into a list of rule dicts."""
    row = (
        await db.execute(
            select(CorpusSnapshot).where(
                CorpusSnapshot.snapshot_date == snapshot_date,
                CorpusSnapshot.source == source,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return []
    text = gzip.decompress(row.payload_gz).decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line]
