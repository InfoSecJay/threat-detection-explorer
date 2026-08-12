"""Tests for JobQueueService.

These tests cover the queue's correctness contract:

- `create_pending_job` inserts a row in `pending` state.
- `claim_next_pending` claims the oldest pending row atomically and
  returns None when nothing is pending.
- A second claim attempt on the same row returns None (i.e. the row
  can't be double-claimed).
- `mark_completed` / `mark_failed` transition the row correctly and
  compute `duration_seconds`.
- `reset_stuck_jobs` sweeps only rows whose `started_at` exceeds the
  timeout, leaving fresher `running` rows alone.
"""

from datetime import datetime, timedelta

import pytest

from app.models.sync_job import SyncJob
from app.services.job_queue import JobQueueService
from app.utils.datetime_utils import utcnow


async def test_create_pending_job_inserts_row(db_session) -> None:
    queue = JobQueueService(db_session)
    job = await queue.create_pending_job(
        job_type="full",
        repository="sublime",
        triggered_by="manual",
    )

    assert job.id
    assert job.status == "pending"
    assert job.repository == "sublime"
    assert job.triggered_by == "manual"
    assert job.started_at is None

    # Confirm it persisted
    fetched = await db_session.get(SyncJob, job.id)
    assert fetched is not None
    assert fetched.status == "pending"


async def test_claim_next_pending_returns_none_when_empty(db_session) -> None:
    queue = JobQueueService(db_session)
    claimed = await queue.claim_next_pending()
    assert claimed is None


async def test_claim_next_pending_transitions_to_running(db_session) -> None:
    queue = JobQueueService(db_session)
    await queue.create_pending_job(job_type="full", repository="sublime")

    claimed = await queue.claim_next_pending()

    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.started_at is not None
    assert claimed.repository == "sublime"


async def test_claim_next_pending_oldest_first(db_session) -> None:
    """When multiple rows are pending, claim the oldest by created_at."""
    queue = JobQueueService(db_session)
    first = await queue.create_pending_job(job_type="full", repository="sigma")
    second = await queue.create_pending_job(job_type="full", repository="elastic")

    claimed = await queue.claim_next_pending()
    assert claimed is not None
    assert claimed.id == first.id
    assert claimed.repository == "sigma"

    # The second row is still pending
    still_pending = await db_session.get(SyncJob, second.id)
    assert still_pending.status == "pending"


async def test_cannot_double_claim_same_row(db_session) -> None:
    """Once claimed, a row should never be returned by claim_next_pending again."""
    queue = JobQueueService(db_session)
    await queue.create_pending_job(job_type="full", repository="sublime")

    first_claim = await queue.claim_next_pending()
    assert first_claim is not None

    # No more pending rows — should be None
    second_claim = await queue.claim_next_pending()
    assert second_claim is None


async def test_mark_completed_sets_status_and_duration(db_session) -> None:
    queue = JobQueueService(db_session)
    await queue.create_pending_job(job_type="full", repository="sublime")
    claimed = await queue.claim_next_pending()
    assert claimed is not None

    await queue.mark_completed(
        claimed.id,
        rules_discovered=100,
        rules_stored=95,
        error_count=0,
        warning_count=2,
    )

    final = await db_session.get(SyncJob, claimed.id)
    assert final.status == "completed"
    assert final.completed_at is not None
    assert final.duration_seconds is not None
    assert final.duration_seconds >= 0
    assert final.rules_discovered == 100
    assert final.rules_stored == 95
    assert final.warning_count == 2


async def test_mark_failed_records_error_message(db_session) -> None:
    queue = JobQueueService(db_session)
    await queue.create_pending_job(job_type="full", repository="sentinel")
    claimed = await queue.claim_next_pending()
    assert claimed is not None

    await queue.mark_failed(claimed.id, "git clone failed: network timeout")

    final = await db_session.get(SyncJob, claimed.id)
    assert final.status == "failed"
    assert final.error_message == "git clone failed: network timeout"
    assert final.error_count == 1
    assert final.completed_at is not None


async def test_mark_failed_truncates_long_error_messages(db_session) -> None:
    """Very long error messages should be truncated to fit the column."""
    queue = JobQueueService(db_session)
    await queue.create_pending_job(job_type="full")
    claimed = await queue.claim_next_pending()
    assert claimed is not None

    huge_error = "x" * 5000
    await queue.mark_failed(claimed.id, huge_error)

    final = await db_session.get(SyncJob, claimed.id)
    assert final.error_message is not None
    assert len(final.error_message) <= 2000


async def test_reset_stuck_jobs_only_affects_old_running_rows(db_session) -> None:
    """A stuck-job sweep should reset old running rows but leave fresh ones."""
    old_started = utcnow() - timedelta(hours=2)
    fresh_started = utcnow() - timedelta(seconds=10)

    # One stuck job (old started_at), one fresh running job
    stuck = SyncJob(
        job_type="full",
        repository="sentinel",
        triggered_by="scheduled",
        status="running",
        started_at=old_started,
    )
    fresh = SyncJob(
        job_type="full",
        repository="sigma",
        triggered_by="manual",
        status="running",
        started_at=fresh_started,
    )
    db_session.add_all([stuck, fresh])
    await db_session.commit()

    queue = JobQueueService(db_session)
    swept = await queue.reset_stuck_jobs(timeout_minutes=30)

    assert len(swept) == 1
    assert swept[0]["id"] == stuck.id
    assert swept[0]["job_type"] == "full"
    assert swept[0]["repository"] == "sentinel"
    assert swept[0]["triggered_by"] == "scheduled"

    await db_session.refresh(stuck)
    await db_session.refresh(fresh)
    assert stuck.status == "failed"
    assert stuck.error_message and "exceeded" in stuck.error_message
    assert fresh.status == "running"  # untouched


async def test_reset_stuck_jobs_ignores_pending_and_completed(db_session) -> None:
    """Rows that aren't in `running` state are never touched."""
    old = utcnow() - timedelta(hours=2)

    pending_old = SyncJob(
        job_type="full",
        triggered_by="manual",
        status="pending",
        started_at=None,
    )
    completed_old = SyncJob(
        job_type="full",
        triggered_by="manual",
        status="completed",
        started_at=old,
        completed_at=old,
    )
    db_session.add_all([pending_old, completed_old])
    await db_session.commit()

    queue = JobQueueService(db_session)
    swept = await queue.reset_stuck_jobs(timeout_minutes=30)

    assert swept == []

    await db_session.refresh(pending_old)
    await db_session.refresh(completed_old)
    assert pending_old.status == "pending"
    assert completed_old.status == "completed"
