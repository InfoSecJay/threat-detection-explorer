"""Acquire / renew / release the sync worker lease (issue #36).

All mutations are conditional UPDATEs (or an INSERT that may lose a
race), so two workers hitting the table at the same instant cannot
both believe they hold it. Portable across SQLite and Postgres.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.worker_lease import WorkerLease
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

SYNC_LEASE_ID = "sync"


class LeaseService:
    def __init__(self, db: AsyncSession, lease_id: str = SYNC_LEASE_ID) -> None:
        self.db = db
        self.lease_id = lease_id

    async def try_acquire(self, owner: str, ttl_seconds: int) -> tuple[bool, bool]:
        """Return ``(held, acquired_now)``.

        - No row: insert one. Losing the insert race means someone
          else just took it -> (False, False).
        - Row owned by us: renew the heartbeat -> (True, False).
        - Row owned by someone else whose heartbeat is older than the
          TTL: conditional takeover keyed on the stale (owner,
          heartbeat) pair -> (True, True) if our UPDATE landed.
        - Otherwise the holder is alive -> (False, False).
        """
        now = utcnow()
        row = await self.db.get(WorkerLease, self.lease_id)
        if row is None:
            self.db.add(WorkerLease(
                id=self.lease_id, owner=owner, acquired_at=now, heartbeat_at=now,
            ))
            try:
                await self.db.commit()
            except IntegrityError:
                await self.db.rollback()
                return (False, False)
            return (True, True)

        if row.owner == owner:
            row.heartbeat_at = now
            await self.db.commit()
            return (True, False)

        if row.heartbeat_at >= now - timedelta(seconds=ttl_seconds):
            return (False, False)

        result = await self.db.execute(
            update(WorkerLease)
            .where(WorkerLease.id == self.lease_id)
            .where(WorkerLease.owner == row.owner)
            .where(WorkerLease.heartbeat_at == row.heartbeat_at)
            .values(owner=owner, acquired_at=now, heartbeat_at=now)
        )
        await self.db.commit()
        if (result.rowcount or 0) == 0:
            return (False, False)
        logger.warning(
            f"Took over sync lease from {row.owner} (last heartbeat "
            f"{row.heartbeat_at.isoformat()}, ttl {ttl_seconds}s)"
        )
        return (True, True)

    async def heartbeat(self, owner: str) -> bool:
        """Renew our heartbeat. False if we no longer own the lease."""
        result = await self.db.execute(
            update(WorkerLease)
            .where(WorkerLease.id == self.lease_id)
            .where(WorkerLease.owner == owner)
            .values(heartbeat_at=utcnow())
        )
        await self.db.commit()
        return (result.rowcount or 0) > 0

    async def release(self, owner: str) -> bool:
        """Expire our own lease so a successor can take over at once
        instead of waiting out the TTL. False if we did not own it."""
        result = await self.db.execute(
            update(WorkerLease)
            .where(WorkerLease.id == self.lease_id)
            .where(WorkerLease.owner == owner)
            .values(heartbeat_at=utcnow() - timedelta(days=1))
        )
        await self.db.commit()
        return (result.rowcount or 0) > 0

    async def current(self) -> WorkerLease | None:
        return await self.db.get(WorkerLease, self.lease_id)


async def get_lease_status(db: AsyncSession, ttl_seconds: int) -> dict:
    """Read-only view for the API/health surfaces."""
    row = await db.get(WorkerLease, SYNC_LEASE_ID)
    if row is None:
        return {"held": False, "owner": None, "heartbeat_at": None, "stale": True}
    age = (utcnow() - row.heartbeat_at).total_seconds()
    return {
        "held": age <= ttl_seconds,
        "owner": row.owner,
        "heartbeat_at": row.heartbeat_at,
        "stale": age > ttl_seconds,
    }
