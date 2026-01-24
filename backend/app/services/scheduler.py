"""Scheduled job service for automatic sync and ingestion."""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_maker
from app.models.sync_job import SyncJob
from app.services.repository_sync import RepositorySyncService
from app.services.ingestion import IngestionService

logger = logging.getLogger(__name__)

ALL_REPOSITORIES = ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm"]


class SchedulerService:
    """Service for managing scheduled sync and ingestion jobs."""

    _instance: Optional["SchedulerService"] = None
    _scheduler: Optional[AsyncIOScheduler] = None
    _is_running: bool = False

    def __new__(cls):
        """Singleton pattern to ensure only one scheduler instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the scheduler."""
        if self._scheduler is None:
            self._scheduler = AsyncIOScheduler()
            self._setup_jobs()

    def _setup_jobs(self):
        """Set up scheduled jobs."""
        # Daily full sync at configured time (default 2 AM UTC)
        self._scheduler.add_job(
            self._run_full_sync,
            CronTrigger(
                hour=settings.sync_schedule_hour,
                minute=settings.sync_schedule_minute,
            ),
            id="daily_full_sync",
            name="Daily Full Sync",
            replace_existing=True,
        )
        logger.info(
            f"Scheduled daily sync at {settings.sync_schedule_hour:02d}:{settings.sync_schedule_minute:02d} UTC"
        )

    def start(self):
        """Start the scheduler."""
        if not self._is_running:
            self._scheduler.start()
            self._is_running = True
            logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler."""
        if self._is_running:
            self._scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Scheduler stopped")

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._is_running

    def get_next_run_time(self) -> Optional[datetime]:
        """Get the next scheduled run time."""
        job = self._scheduler.get_job("daily_full_sync")
        if job:
            return job.next_run_time
        return None

    async def _run_full_sync(self):
        """Run a full sync and ingestion for all repositories."""
        logger.info("Starting scheduled full sync")
        await self.run_full_sync_job(triggered_by="scheduled")

    async def run_full_sync_job(
        self,
        triggered_by: str = "manual",
        repository: Optional[str] = None,
    ) -> SyncJob:
        """Run a full sync and ingestion job.

        Args:
            triggered_by: How the job was triggered ("manual", "scheduled", "webhook")
            repository: Specific repository to sync, or None for all

        Returns:
            The SyncJob record with results
        """
        async with async_session_maker() as db:
            # Create job record
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
            logger.info(f"Created sync job {job_id}")

            try:
                repos_to_sync = [repository] if repository else ALL_REPOSITORIES
                total_discovered = 0
                total_stored = 0
                total_errors = 0
                total_warnings = 0
                repo_results = {}

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
                        # Step 1: Sync repository (git pull)
                        logger.info(f"Syncing repository: {repo_name}")
                        sync_success, sync_message = await sync_service.sync_repository(repo_name)
                        repo_result["sync_success"] = sync_success
                        repo_result["message"] = sync_message

                        if not sync_success:
                            logger.warning(f"Sync failed for {repo_name}: {sync_message}")
                            total_errors += 1
                            repo_results[repo_name] = repo_result
                            continue

                        # Step 2: Ingest rules
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
                            f"Completed {repo_name}: stored={stats.stored}, errors={stats.error_count}"
                        )

                    except Exception as e:
                        logger.error(f"Error processing {repo_name}: {e}")
                        repo_result["message"] = str(e)
                        total_errors += 1

                    repo_results[repo_name] = repo_result

                # Update job with results
                job = await db.get(SyncJob, job_id)
                job.status = "completed"
                job.completed_at = datetime.utcnow()
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
                logger.error(f"Sync job {job_id} failed: {e}")
                job = await db.get(SyncJob, job_id)
                job.status = "failed"
                job.completed_at = datetime.utcnow()
                job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
                job.error_message = str(e)
                job.error_count = 1
                await db.commit()
                return job


async def get_sync_job_history(
    db: AsyncSession,
    limit: int = 20,
    repository: Optional[str] = None,
) -> list[SyncJob]:
    """Get recent sync job history.

    Args:
        db: Database session
        limit: Maximum number of jobs to return
        repository: Filter by repository name

    Returns:
        List of SyncJob records
    """
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
    """Get the last successful sync job.

    Args:
        db: Database session
        repository: Filter by repository name

    Returns:
        The last successful SyncJob or None
    """
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


# Global scheduler instance
scheduler = SchedulerService()
