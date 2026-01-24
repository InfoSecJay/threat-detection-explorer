"""Scheduler and sync job API routes."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings
from app.services.scheduler import (
    scheduler,
    get_sync_job_history,
    get_last_successful_sync,
)

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


class SchedulerStatusResponse(BaseModel):
    """Response model for scheduler status."""

    enabled: bool
    running: bool
    next_run_time: Optional[datetime]
    schedule_hour: int
    schedule_minute: int


class SyncJobResponse(BaseModel):
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
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class TriggerSyncRequest(BaseModel):
    """Request model for triggering a sync."""

    repository: Optional[str] = None  # None means all repositories


class TriggerSyncResponse(BaseModel):
    """Response model for triggered sync."""

    message: str
    job_id: str


@router.get("/status", response_model=SchedulerStatusResponse)
async def get_scheduler_status():
    """Get the current scheduler status."""
    return SchedulerStatusResponse(
        enabled=settings.enable_scheduler,
        running=scheduler.is_running,
        next_run_time=scheduler.get_next_run_time(),
        schedule_hour=settings.sync_schedule_hour,
        schedule_minute=settings.sync_schedule_minute,
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
    from app.models.sync_job import SyncJob

    job = await db.get(SyncJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Sync job not found")
    return SyncJobResponse.model_validate(job)


async def _run_sync_in_background(repository: Optional[str], job_id: str):
    """Background task to run sync."""
    await scheduler.run_full_sync_job(
        triggered_by="manual",
        repository=repository,
    )


@router.post("/trigger", response_model=TriggerSyncResponse)
async def trigger_sync(
    request: TriggerSyncRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a manual sync and ingestion.

    This will run in the background and return immediately.
    Use the returned job_id to check status via GET /jobs/{job_id}
    """
    from app.models.sync_job import SyncJob

    # Validate repository if specified
    if request.repository:
        valid_repos = ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm"]
        if request.repository not in valid_repos:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid repository: {request.repository}. Valid options: {valid_repos}",
            )

    # Create a pending job record
    job = SyncJob(
        job_type="full",
        repository=request.repository,
        triggered_by="manual",
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Run sync in background
    background_tasks.add_task(
        scheduler.run_full_sync_job,
        triggered_by="manual",
        repository=request.repository,
    )

    repo_name = request.repository or "all repositories"
    return TriggerSyncResponse(
        message=f"Sync triggered for {repo_name}. Check job status for progress.",
        job_id=job.id,
    )


@router.post("/start")
async def start_scheduler():
    """Start the scheduler (if not already running)."""
    if scheduler.is_running:
        return {"message": "Scheduler is already running"}

    scheduler.start()
    return {
        "message": "Scheduler started",
        "next_run_time": scheduler.get_next_run_time(),
    }


@router.post("/stop")
async def stop_scheduler():
    """Stop the scheduler."""
    if not scheduler.is_running:
        return {"message": "Scheduler is not running"}

    scheduler.stop()
    return {"message": "Scheduler stopped"}
