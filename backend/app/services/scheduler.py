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
from app.services.ingestion_errors import ErrorStage
from app.services.parse_failure_notifier import notify_parse_failures
from app.services.repository_sync import ALL_REPOSITORY_NAMES, RepositorySyncService
from app.services.taxonomy_notifier import notify_drift
from app.services.upstream_verifier import verify_upstream
from app.utils.datetime_utils import utcnow

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
                job.started_at = job.started_at or utcnow()
                await db.commit()
        else:
            # Inline path: create a fresh row (tests, ad-hoc scripts).
            job = SyncJob(
                job_type="full",
                repository=repository,
                triggered_by=triggered_by,
                status="running",
                started_at=utcnow(),
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
            # Job-level conditions from the post-sync notifiers (#46).
            # Persisted on `sync_jobs.warnings` so the API/UI can show
            # e.g. "GitHub token expired" without reading worker logs.
            job_warnings: list[dict] = []

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
                    "taxonomy_matched": 0,
                    "taxonomy_unmatched": 0,
                    "taxonomy_coverage_percent": 0.0,
                    "taxonomy_unmatched_by_fingerprint": {},
                    # Parse-failure surface for #30 notifier -- silent
                    # PARSE/NORMALIZE regressions used to be invisible
                    # because errors sat inside IngestionStats.errors
                    # and were never persisted anywhere queryable.
                    "parse_failure_count": 0,
                    "parse_failure_samples": [],
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
                    stats = await ingestion_service.ingest_repository(
                        repo_name, sync_run_id=str(job_id),
                    )

                    repo_result["ingest_success"] = stats.stored > 0
                    repo_result["rules_discovered"] = stats.discovered
                    repo_result["rules_stored"] = stats.stored
                    repo_result["errors"] = stats.error_count
                    repo_result["warnings"] = stats.warning_count
                    repo_result["message"] = f"Stored {stats.stored} rules"
                    repo_result["taxonomy_matched"] = stats.taxonomy_matched_count
                    repo_result["taxonomy_unmatched"] = stats.taxonomy_unmatched_count
                    repo_result["taxonomy_coverage_percent"] = round(
                        stats.taxonomy_coverage_percent, 2
                    )
                    repo_result["taxonomy_unmatched_by_fingerprint"] = (
                        stats.taxonomy_unmatched_by_fingerprint
                    )

                    # Extract PARSE/NORMALIZE failures for the #30
                    # notifier. Sample list is capped so the JSON blob
                    # on sync_jobs.repository_results stays bounded
                    # even if a parser regresses hard on a whole repo.
                    parse_failures = [
                        e for e in stats.errors
                        if e.stage in (ErrorStage.PARSE, ErrorStage.NORMALIZE)
                    ]
                    repo_result["parse_failure_count"] = len(parse_failures)
                    repo_result["parse_failure_samples"] = [
                        {
                            "file_path": str(e.file_path),
                            "stage": e.stage.value,
                            "severity": e.severity.value,
                            "message": (e.message or "")[:300],
                        }
                        for e in parse_failures[:30]
                    ]

                    total_discovered += stats.discovered
                    total_stored += stats.stored
                    total_errors += stats.error_count
                    total_warnings += stats.warning_count

                    logger.info(
                        f"Completed {repo_name}: stored={stats.stored}, "
                        f"errors={stats.error_count}, "
                        f"taxonomy_coverage={stats.taxonomy_coverage_percent:.1f}% "
                        f"({stats.taxonomy_unmatched_count} unmapped)"
                    )

                except Exception as e:
                    logger.error(f"Error processing {repo_name}: {e}", exc_info=True)
                    repo_result["message"] = str(e)
                    total_errors += 1

                repo_results[repo_name] = repo_result

            # Persist final results on the job row.
            job = await db.get(SyncJob, job_id)
            job.status = "completed"
            job.completed_at = utcnow()
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

            # Daily MITRE coverage snapshot (issue #9): one
            # technique x source x rule_count row-set per day, feeding
            # the /trending/newly-covered diff. Same failure isolation
            # as the notifiers below -- a snapshot bug never degrades
            # the sync's completed status.
            try:
                from app.services.coverage_snapshot import write_coverage_snapshot
                await write_coverage_snapshot(db)
            except Exception as e:
                logger.warning(f"Coverage snapshot failed: {e}", exc_info=True)

            # Taxonomy drift notifications (Issue 2 observability layer).
            # Opens/updates GitHub issues for any repo with unmapped
            # rules. Feature-flagged off by default; no-ops if the
            # notifier isn't configured. Wrapped in a try so a notifier
            # bug never degrades the sync's completed status.
            try:
                job_warnings.extend(await notify_drift(repo_results, str(job_id)) or [])
            except Exception as e:
                logger.warning(f"Taxonomy drift notifier raised: {e}", exc_info=True)

            # Parse-failure notifications (#30). Alerts when a source's
            # ingest success rate drops below tolerance -- catches
            # silent PARSE/NORMALIZE regressions that used to disappear
            # into IngestionStats.errors. Same feature flag + isolation
            # semantics as notify_drift.
            try:
                job_warnings.extend(
                    await notify_parse_failures(repo_results, str(job_id)) or []
                )
            except Exception as e:
                logger.warning(
                    f"Parse-failure notifier raised: {e}", exc_info=True
                )

            # Upstream tree verification (#29). Cross-checks our
            # discovered count against what our patterns would match
            # on the upstream GitHub tree, plus flags per-directory
            # scope drift vs the previous sync. Same feature flag,
            # same failure isolation as notify_drift. Mutates
            # `repo_results` in place to add verification metadata.
            try:
                previous_results = await _load_previous_repo_results(db, job_id)
                job_warnings.extend(
                    await verify_upstream(repo_results, str(job_id), previous_results)
                    or []
                )
            except Exception as e:
                logger.warning(f"Upstream verifier raised: {e}", exc_info=True)

            # Re-persist so the verification metadata + directory counts
            # land on the job row for the next diff, and the job-level
            # warnings collected above become visible via the API.
            try:
                job = await db.get(SyncJob, job_id)
                job.repository_results = repo_results
                job.warnings = job_warnings
                await db.commit()
            except Exception as e:
                logger.warning(
                    f"Persisting post-sync metadata failed: {e}", exc_info=True
                )

            if job_warnings:
                logger.error(
                    f"Sync job {job_id} completed with {len(job_warnings)} "
                    f"job-level warning(s): "
                    + "; ".join(w.get("message", "") for w in job_warnings)
                )

            return job

        except Exception as e:
            logger.error(f"Sync job {job_id} failed: {e}", exc_info=True)
            job = await db.get(SyncJob, job_id)
            job.status = "failed"
            job.completed_at = utcnow()
            if job.started_at:
                job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            job.error_message = str(e)[:2000]
            job.error_count = 1
            await db.commit()
            return job


async def _load_previous_repo_results(
    db: AsyncSession, current_job_id,
) -> Optional[dict]:
    """Fetch `repository_results` from the most recent COMPLETED sync job
    that isn't the current one. Powers the per-directory diff in the
    upstream verifier — without a previous baseline we can't flag
    NEW / VANISHED directories."""
    result = await db.execute(
        select(SyncJob)
        .where(SyncJob.status == "completed")
        .where(SyncJob.id != current_job_id)
        .order_by(desc(SyncJob.completed_at))
        .limit(1)
    )
    prev = result.scalar_one_or_none()
    return prev.repository_results if prev else None


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
