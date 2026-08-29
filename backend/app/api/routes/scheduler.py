"""Scheduler and sync job API routes.

These routes are read/write interfaces to the `sync_jobs` table plus a
small `/status` informational endpoint. They do NOT execute sync work
themselves — that has moved to the dedicated worker service (see
`app.worker`). The API only creates pending job rows; the worker polls
and processes them.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import UtcTimestampsModel
from app.database import get_db
from app.config import settings
from app.models.sync_job import SyncJob
from app.services.job_queue import JobQueueService
from app.services.repository_sync import ALL_REPOSITORY_NAMES
from app.utils.datetime_utils import utcnow
from app.services.scheduler import (
    get_last_successful_sync,
    get_sync_job_history,
)

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


class SchedulerStatusResponse(UtcTimestampsModel):
    """Response model for scheduler status."""

    enabled: bool
    schedule_hour: int
    schedule_minute: int
    schedule_timezone: str
    next_run_time: Optional[datetime]
    last_scheduled_run: Optional[datetime]
    message: str
    # Single-flight sync lease (#36): which worker may run jobs right
    # now. `held` false + `owner` set means the last holder died and a
    # successor has not taken over yet.
    worker_lease: Optional[dict] = None


class SyncJobResponse(UtcTimestampsModel):
    """Response model for sync job details."""

    id: str
    job_type: str
    repository: Optional[str]
    triggered_by: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    rules_discovered: int
    rules_stored: int
    error_count: int
    warning_count: int
    repository_results: Optional[dict]
    # Job-level conditions (#46), e.g. {"code": "github_auth_failed",
    # "source": "upstream_verifier", "message": "..."}. Always a list in
    # the response; see the validator for why.
    warnings: list[dict] = []
    error_message: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("warnings", mode="before")
    @classmethod
    def _coerce_warnings(cls, value):
        """Rows older than the column are NULL (Postgres, pre-migration
        reads) or `[]` (startup migration default). Both must serialize
        as an empty list, never 500 the jobs endpoint -- the 2026-08-28
        detail-page outage was exactly this class of legacy-shape bug."""
        if not isinstance(value, list):
            return []
        return [w for w in value if isinstance(w, dict)]


class TriggerSyncRequest(BaseModel):
    """Request model for triggering a sync."""

    repository: Optional[str] = None  # None means all repositories


class TriggerSyncResponse(BaseModel):
    """Response model for triggered sync."""

    message: str
    job_id: str


def _compute_next_run(now: datetime) -> datetime:
    """Compute the next cron fire time from settings alone.

    The API process no longer hosts APScheduler, so we can't ask "when
    does the next run happen?" — we derive it from the same config the
    worker uses. Accurate to the minute, which is all the UI needs.

    The schedule hour/minute are local to `sync_schedule_timezone`
    (matching the worker's CronTrigger); the result is converted back
    to naive UTC, the storage convention for every timestamp this API
    returns.
    """
    tz = ZoneInfo(settings.sync_schedule_timezone)
    now_local = now.replace(tzinfo=timezone.utc).astimezone(tz)
    candidate = now_local.replace(
        hour=settings.sync_schedule_hour,
        minute=settings.sync_schedule_minute,
        second=0,
        microsecond=0,
    )
    if candidate <= now_local:
        candidate += timedelta(days=1)
    return candidate.astimezone(timezone.utc).replace(tzinfo=None)


@router.get("/status", response_model=SchedulerStatusResponse)
async def get_scheduler_status(db: AsyncSession = Depends(get_db)):
    """Return the nightly scheduler's configuration and recent activity.

    Because the nightly scheduler now runs in the dedicated worker
    service, this endpoint reports config-derived state (enabled flag,
    schedule hour/minute, next run time) plus the timestamp of the most
    recent scheduled run observed in the database.
    """
    now = utcnow()

    last_scheduled_result = await db.execute(
        select(SyncJob.started_at)
        .where(SyncJob.triggered_by == "scheduled")
        .where(SyncJob.started_at.is_not(None))
        .order_by(desc(SyncJob.started_at))
        .limit(1)
    )
    last_scheduled = last_scheduled_result.scalar_one_or_none()

    from app.services.worker_lease import get_lease_status
    from app.utils.datetime_utils import to_utc_iso
    from app.worker import LEASE_TTL_SECONDS

    lease = await get_lease_status(db, LEASE_TTL_SECONDS)
    lease["heartbeat_at"] = to_utc_iso(lease["heartbeat_at"])

    return SchedulerStatusResponse(
        worker_lease=lease,
        enabled=settings.enable_scheduler,
        schedule_hour=settings.sync_schedule_hour,
        schedule_minute=settings.sync_schedule_minute,
        schedule_timezone=settings.sync_schedule_timezone,
        next_run_time=_compute_next_run(now) if settings.enable_scheduler else None,
        last_scheduled_run=last_scheduled,
        message=(
            "Nightly sync runs in the worker service. The API no longer "
            "hosts an in-process scheduler."
        ),
    )


@router.get("/jobs", response_model=list[SyncJobResponse])
async def get_sync_jobs(
    limit: int = 20,
    repository: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get recent sync job history.

    Args:
        limit: Maximum number of jobs to return (default 20)
        repository: Filter by repository name
    """
    jobs = await get_sync_job_history(db, limit=limit, repository=repository)
    return [SyncJobResponse.model_validate(job) for job in jobs]


@router.get("/jobs/latest", response_model=Optional[SyncJobResponse])
async def get_latest_sync(
    repository: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get the latest successful sync job."""
    job = await get_last_successful_sync(db, repository=repository)
    if job:
        return SyncJobResponse.model_validate(job)
    return None


@router.get("/jobs/{job_id}", response_model=SyncJobResponse)
async def get_sync_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific sync job."""
    job = await db.get(SyncJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Sync job not found")
    return SyncJobResponse.model_validate(job)


@router.post("/trigger", response_model=TriggerSyncResponse, status_code=202)
async def trigger_sync(
    request: TriggerSyncRequest,
    db: AsyncSession = Depends(get_db),
):
    """Queue a manual sync job for the worker to pick up.

    This endpoint only INSERTs a pending row into `sync_jobs`; the
    worker process polls for pending rows and runs the actual sync.
    Returns 202 Accepted with the `job_id`; clients can poll
    GET /jobs/{job_id} to see progress.
    """
    if request.repository and request.repository not in ALL_REPOSITORY_NAMES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid repository: {request.repository}. "
                f"Valid options: {ALL_REPOSITORY_NAMES}"
            ),
        )

    queue = JobQueueService(db)
    job = await queue.create_pending_job(
        job_type="full",
        repository=request.repository,
        triggered_by="manual",
    )

    repo_name = request.repository or "all repositories"
    return TriggerSyncResponse(
        message=(
            f"Sync queued for {repo_name}. The worker will pick it up "
            f"within a few seconds."
        ),
        job_id=job.id,
    )
