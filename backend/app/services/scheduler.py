"""Sync job execution logic.

Historically this module also hosted an in-process APScheduler instance
that ran the nightly sync directly inside the FastAPI worker. That design
caused production outages because git clone + ingestion would block the
API event loop for several minutes at a time.

Today this module contains only the business logic that processes a
single sync job — `run_full_sync_job`. It is called from two places:

1. The background worker process (`app.worker`), which polls the
   `sync_jobs` table for pending rows and invokes this function for each
   one it claims. The worker also hosts its own APScheduler instance to
   enqueue the nightly run.

2. Tests and scripts that want to run a sync inline without a worker.

The function accepts an optional `job_id` so callers can pass in a row
that was already created by a different process (the API's /trigger
endpoint creates `status='pending'` rows; the worker claims them and
passes the id in). When `job_id` is None the function creates its own
row, which matches the historical call shape used by tests.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.models.sync_job import SyncJob
from app.services.ingestion import IngestionService
from app.services.repository_sync import ALL_REPOSITORY_NAMES, RepositorySyncService

logger = logging.getLogger(__name__)


async def run_full_sync_job(
    triggered_by: str = "manual",
    repository: Optional[str] = None,
    job_id: Optional[str] = None,
) -> SyncJob:
    """Run a full sync + ingestion cycle and record results on a SyncJob row.

    Args:
        triggered_by: How the job was triggered ("manual", "scheduled",
            "webhook"). Ignored when `job_id` is provided — the row's
            existing value wins.
        repository: Specific repository to process, or None for all.
            Ignored when `job_id` is provided.
        job_id: If provided, operates on the existing SyncJob row with
            that id. The row is expected to already exist; this function
            will transition it to `running` (if it isn't already) and
            then to `completed` or `failed`. If None, creates a new row.

    Returns:
        The SyncJob record in its final state.
    """
    async with async_session_maker() as db:
        if job_id is not None:
            # Worker path: the row already exists, claimed by JobQueueService.
            job = await db.get(SyncJob, job_id)
            if job is None:
                raise ValueError(f"SyncJob {job_id} not found")
            # Honor whatever was persisted on the row.
            triggered_by = job.triggered_by
            repository = job.repository
            if job.status != "running":
                # Defensive: if caller forgot to claim, claim now.
                job.status = "running"
                job.started_at = job.started_at or datetime.utcnow()
                await db.commit()
        else:
            # Inline path: create a fresh row (tests, ad-hoc scripts).
            job = SyncJob(
                job_type="full",
                repository=repository,
                triggered_by=triggered_by,
                status="running",
                started_at=datetime.utcnow(),
            )
            db.add(job)
            await db.commit()
            await db.refresh(job)
            job_id = job.id

        logger.info(
            f"Running sync job {job_id} "
            f"(trigger={triggered_by}, repo={repository or 'ALL'})"
        )

        try:
            repos_to_sync = [repository] if repository else ALL_REPOSITORY_NAMES
            total_discovered = 0
            total_stored = 0
            total_errors = 0
            total_warnings = 0
            repo_results: dict[str, dict] = {}

            sync_service = RepositorySyncService(db)
            ingestion_service = IngestionService(db)

            for repo_name in repos_to_sync:
                repo_result = {
                    "sync_success": False,
                    "ingest_success": False,
                    "rules_discovered": 0,
                    "rules_stored": 0,
                    "errors": 0,
                    "warnings": 0,
                    "message": "",
                }

                try:
                    logger.info(f"Syncing repository: {repo_name}")
                    sync_success, sync_message = await sync_service.sync_repository(repo_name)
                    repo_result["sync_success"] = sync_success
                    repo_result["message"] = sync_message

                    if not sync_success:
                        logger.warning(f"Sync failed for {repo_name}: {sync_message}")
                        total_errors += 1
                        repo_results[repo_name] = repo_result
                        continue

                    logger.info(f"Ingesting rules from: {repo_name}")
                    stats = await ingestion_service.ingest_repository(repo_name)

                    repo_result["ingest_success"] = stats.stored > 0
                    repo_result["rules_discovered"] = stats.discovered
                    repo_result["rules_stored"] = stats.stored
                    repo_result["errors"] = stats.error_count
                    repo_result["warnings"] = stats.warning_count
                    repo_result["message"] = f"Stored {stats.stored} rules"

                    total_discovered += stats.discovered
                    total_stored += stats.stored
                    total_errors += stats.error_count
                    total_warnings += stats.warning_count

                    logger.info(
                        f"Completed {repo_name}: stored={stats.stored}, "
                        f"errors={stats.error_count}"
                    )

                except Exception as e:
                    logger.error(f"Error processing {repo_name}: {e}", exc_info=True)
                    repo_result["message"] = str(e)
                    total_errors += 1

                repo_results[repo_name] = repo_result

            # Persist final results on the job row.
            job = await db.get(SyncJob, job_id)
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            if job.started_at:
                job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            job.rules_discovered = total_discovered
            job.rules_stored = total_stored
            job.error_count = total_errors
            job.warning_count = total_warnings
            job.repository_results = repo_results
            await db.commit()

            logger.info(
                f"Sync job {job_id} completed: "
                f"discovered={total_discovered}, stored={total_stored}, "
                f"errors={total_errors}, duration={job.duration_seconds:.1f}s"
            )

            return job

        except Exception as e:
            logger.error(f"Sync job {job_id} failed: {e}", exc_info=True)
            job = await db.get(SyncJob, job_id)
            job.status = "failed"
            job.completed_at = datetime.utcnow()
            if job.started_at:
                job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            job.error_message = str(e)[:2000]
            job.error_count = 1
            await db.commit()
            return job


async def get_sync_job_history(
    db: AsyncSession,
    limit: int = 20,
    repository: Optional[str] = None,
) -> list[SyncJob]:
    """Return recent sync job history, optionally filtered by repository."""
    query = select(SyncJob).order_by(desc(SyncJob.created_at)).limit(limit)

    if repository:
        query = query.where(
            (SyncJob.repository == repository) | (SyncJob.repository.is_(None))
        )

    result = await db.execute(query)
    return list(result.scalars().all())


async def get_last_successful_sync(
    db: AsyncSession,
    repository: Optional[str] = None,
) -> Optional[SyncJob]:
    """Return the most recent completed sync job, optionally filtered."""
    query = (
        select(SyncJob)
        .where(SyncJob.status == "completed")
        .order_by(desc(SyncJob.completed_at))
        .limit(1)
    )

    if repository:
        query = query.where(
            (SyncJob.repository == repository) | (SyncJob.repository.is_(None))
        )

    result = await db.execute(query)
    return result.scalar_one_or_none()
