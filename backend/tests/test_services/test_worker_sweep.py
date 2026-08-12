"""Tests for Worker._sweep_and_requeue.

A `running` sync job whose worker died (Railway redeploy, OOM) must not
just be marked failed — the lost sync has to be re-queued so the night's
update still happens. The one exception is a job that was ITSELF a
requeue: if it dies again we assume the job is what's crashing the
worker and stop retrying instead of clone-looping forever.
"""

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.worker as worker_module
from app.database import Base
from app.models.sync_job import SyncJob
from app.utils.datetime_utils import utcnow
from app.worker import Worker


@pytest.fixture
async def session_maker(monkeypatch):
    """In-memory DB whose sessionmaker is patched into app.worker."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(worker_module, "async_session_maker", maker)
    yield maker
    await engine.dispose()


async def _add_stuck_job(maker, triggered_by: str, repository=None) -> str:
    async with maker() as db:
        job = SyncJob(
            job_type="full",
            repository=repository,
            triggered_by=triggered_by,
            status="running",
            started_at=utcnow() - timedelta(hours=4),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return job.id


async def _jobs_by_status(maker, status: str) -> list[SyncJob]:
    async with maker() as db:
        result = await db.execute(select(SyncJob).where(SyncJob.status == status))
        return list(result.scalars().all())


async def test_sweep_requeues_scheduled_job(session_maker) -> None:
    stuck_id = await _add_stuck_job(session_maker, "scheduled")

    await Worker()._sweep_and_requeue()

    failed = await _jobs_by_status(session_maker, "failed")
    assert [j.id for j in failed] == [stuck_id]

    pending = await _jobs_by_status(session_maker, "pending")
    assert len(pending) == 1
    assert pending[0].triggered_by == "requeue"
    assert pending[0].job_type == "full"
    assert pending[0].repository is None


async def test_sweep_preserves_repository_scope(session_maker) -> None:
    await _add_stuck_job(session_maker, "manual", repository="auth0")

    await Worker()._sweep_and_requeue()

    pending = await _jobs_by_status(session_maker, "pending")
    assert len(pending) == 1
    assert pending[0].repository == "auth0"


async def test_sweep_does_not_requeue_a_dead_requeue(session_maker) -> None:
    """Second-generation death: mark failed, do NOT create a third run."""
    await _add_stuck_job(session_maker, "requeue")

    await Worker()._sweep_and_requeue()

    failed = await _jobs_by_status(session_maker, "failed")
    assert len(failed) == 1
    pending = await _jobs_by_status(session_maker, "pending")
    assert pending == []


async def test_sweep_ignores_fresh_running_jobs(session_maker) -> None:
    async with session_maker() as db:
        job = SyncJob(
            job_type="full",
            triggered_by="scheduled",
            status="running",
            started_at=utcnow() - timedelta(minutes=5),
        )
        db.add(job)
        await db.commit()

    await Worker()._sweep_and_requeue()

    running = await _jobs_by_status(session_maker, "running")
    assert len(running) == 1
    assert await _jobs_by_status(session_maker, "pending") == []
