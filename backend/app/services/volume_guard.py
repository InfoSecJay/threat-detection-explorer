"""Disk-pressure guard for the Postgres volume (#97).

Postgres cannot see free disk, and a full volume does not fail cleanly:
it PANICs mid-transaction, and on 2026-08-31 the end-of-recovery
checkpoint could not even write its temp file, so the crash loop never
ended (five hours of 500s). The only number we can read from inside a
session is ``pg_database_size``, so callers compare it against the
configured volume size (``POSTGRES_VOLUME_MB``) and back off before the
kernel says no.

Two consumers, two thresholds:

- the corpus snapshot (the one optional, unbounded writer) stops at
  ``SNAPSHOT_CAP_SHARE`` so the sync itself keeps running;
- the sync refuses to start at ``SYNC_REFUSE_SHARE`` -- a stale corpus
  for one night beats a PANIC mid-upsert, which on 2026-09-02 also
  tombstoned 176 live rules.

Both are no-ops outside Postgres (SQLite dev/tests).
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings

logger = logging.getLogger(__name__)

SNAPSHOT_CAP_SHARE = 0.7
SYNC_REFUSE_SHARE = 0.85


class VolumeNearlyFull(RuntimeError):
    """Raised by ``refuse_sync_if_volume_nearly_full``; the message is
    what lands on ``sync_jobs.error_message``."""


async def database_size_bytes(db: AsyncSession) -> Optional[int]:
    """``pg_database_size(current_database())``, or None off Postgres."""
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return None
    return (await db.execute(text("SELECT pg_database_size(current_database())"))).scalar() or 0


async def database_over_share(db: AsyncSession, share: float) -> Optional[tuple[int, int]]:
    """Return ``(size_bytes, cap_bytes)`` when the database exceeds
    ``share`` of the configured volume, else None."""
    size = await database_size_bytes(db)
    if size is None:
        return None
    cap = int(settings.postgres_volume_mb * 1024 * 1024 * share)
    if size <= cap:
        return None
    return size, cap


async def refuse_sync_if_volume_nearly_full(db: AsyncSession) -> None:
    """Raise ``VolumeNearlyFull`` before a sync touches the corpus."""
    over = await database_over_share(db, SYNC_REFUSE_SHARE)
    if over is None:
        return
    size, _cap = over
    raise VolumeNearlyFull(
        f"Sync refused: database is {size / 1_048_576:.0f}MB, over "
        f"{SYNC_REFUSE_SHARE:.0%} of the {settings.postgres_volume_mb}MB volume "
        f"(POSTGRES_VOLUME_MB). A full volume PANICs Postgres mid-upsert; grow "
        f"the Railway volume, set POSTGRES_VOLUME_MB, then re-trigger the sync."
    )
