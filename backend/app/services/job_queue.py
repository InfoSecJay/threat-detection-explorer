"""Job queue backed by the sync_jobs table.

This module implements a minimal database-backed work queue for sync and
ingestion jobs. There is intentionally no Redis, Celery, or RQ in play:
the `sync_jobs` table (which already tracked job status for UI purposes)
is reused as the queue storage, which keeps the deployment surface tiny
and lets the worker process poll the same Postgres instance the API
writes to.

Concurrency model:

- The API creates jobs with `status="pending"` via `create_pending_job`.
- The worker process calls `claim_next_pending()` on a poll loop. Claim
  is atomic via a conditional `UPDATE sync_jobs SET status='running'
  WHERE id=:id AND status='pending'` — if two workers race, only one
  row update succeeds and the loser gets `None` back.
- Workers that die mid-job leave rows stuck in `running`.
  `reset_stuck_jobs()` is called at worker startup to sweep any row
  whose `started_at` is older than a timeout back to `failed`.

The conditional-update pattern works on both Postgres and SQLite, which
means local development against SQLite behaves identically to production
against Postgres. Postgres-specific optimizations like `FOR UPDATE SKIP
LOCKED` are intentionally avoided.
"""

from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sync_job import SyncJob
from app.utils.datetime_utils import utcnow


class JobQueueService:
    """Thin wrapper around sync_jobs rows for queue operations."""

    def __init__(self, db: AsyncSession):
        """Initialize with an AsyncSession. Caller manages the session lifecycle."""
        self.db = db

    async def create_pending_job(
        self,
        job_type: str,
        repository: Optional[str] = None,
        triggered_by: str = "manual",
    ) -> SyncJob:
        """Insert a new pending job row.

        Called from the API's /trigger endpoint. Returns the persisted row
        with its server-assigned id so the caller can return it to the
        client for polling.
        """
        job = SyncJob(
            job_type=job_type,
            repository=repository,
            triggered_by=triggered_by,
            status="pending",
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def claim_next_pending(self) -> Optional[SyncJob]:
        """Atomically claim the oldest pending job.

        Returns the claimed `SyncJob` row with `status='running'` and
        `started_at` set, or `None` if there are no pending jobs. Safe to
        call from multiple workers: at most one caller gets a given row.

        Implementation: SELECT the oldest pending row, then run a
        conditional UPDATE that only succeeds if the row is still pending.
        If the UPDATE affects zero rows, another worker beat us and we
        return None — the caller will try again on the next poll cycle.
        """
        result = await self.db.execute(
            select(SyncJob.id)
            .where(SyncJob.status == "pending")
            .order_by(SyncJob.created_at.asc())
            .limit(1)
        )
        row = result.first()
        if not row:
            return None

        job_id = row[0]
        now = utcnow()

        # The `status='pending'` guard is what makes this safe against
        # concurrent claim attempts. Whichever worker's UPDATE lands first
        # wins; any losing UPDATE reports 0 rows affected.
        claim_result = await self.db.execute(
            update(SyncJob)
            .where(SyncJob.id == job_id)
            .where(SyncJob.status == "pending")
            .values(status="running", started_at=now)
        )
        await self.db.commit()

        if (claim_result.rowcount or 0) == 0:
            # Lost the race, no harm done.
            return None

        # Reload the full row with its new state.
        return await self.db.get(SyncJob, job_id)

    async def mark_completed(
        self,
        job_id: str,
        **fields: Any,
    ) -> None:
        """Mark a running job as completed.

        Accepts arbitrary keyword arguments that are forwarded into the
        UPDATE (e.g. `rules_discovered`, `rules_stored`, `error_count`,
        `warning_count`, `repository_results`). `completed_at` and
        `duration_seconds` are computed here so the caller doesn't have
        to remember to set them.
        """
        now = utcnow()
        job = await self.db.get(SyncJob, job_id)
        duration = None
        if job and job.started_at:
            duration = (now - job.started_at).total_seconds()

        values: dict[str, Any] = {
            "status": "completed",
            "completed_at": now,
            "duration_seconds": duration,
        }
        values.update(fields)

        await self.db.execute(
            update(SyncJob).where(SyncJob.id == job_id).values(**values)
        )
        await self.db.commit()

    async def mark_failed(self, job_id: str, error_message: str) -> None:
        """Mark a running job as failed with an error message.

        `error_message` is truncated to fit the column and stored as-is;
        the caller is responsible for including enough context to
        diagnose without exposing secrets (stack traces are OK).
        """
        now = utcnow()
        job = await self.db.get(SyncJob, job_id)
        duration = None
        if job and job.started_at:
            duration = (now - job.started_at).total_seconds()

        await self.db.execute(
            update(SyncJob)
            .where(SyncJob.id == job_id)
            .values(
                status="failed",
                completed_at=now,
                duration_seconds=duration,
                error_message=error_message[:2000],
                error_count=1,
            )
        )
        await self.db.commit()

    async def reset_stuck_jobs(self, timeout_minutes: int = 30) -> int:
        """Sweep `running` jobs whose `started_at` exceeds the timeout.

        Called once at worker startup to clean up after a previous worker
        that died mid-job (e.g. container killed by Railway, OOM, etc.).
        Any row older than `timeout_minutes` is moved to `failed` so the
        next poll cycle can pick up fresh work without ambiguity.

        Returns the number of rows that were reset.
        """
        cutoff = utcnow() - timedelta(minutes=timeout_minutes)
        result = await self.db.execute(
            update(SyncJob)
            .where(SyncJob.status == "running")
            .where(SyncJob.started_at < cutoff)
            .values(
                status="failed",
                completed_at=utcnow(),
                error_message=(
                    f"Job reset by worker startup — exceeded "
                    f"{timeout_minutes}m timeout (previous worker likely crashed)"
                ),
                error_count=1,
            )
        )
        await self.db.commit()
        return result.rowcount or 0
