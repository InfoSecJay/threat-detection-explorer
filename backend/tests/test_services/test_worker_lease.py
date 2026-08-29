"""Sync worker single-flight lease (#36).

Two worker containers overlap during a Railway deploy and share the
repos volume. The lease guarantees only one claims jobs, and lets the
successor requeue the dead holder's running job immediately instead of
after the 180-minute stuck timeout.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.worker as worker_module
from app.database import Base
from app.models.sync_job import SyncJob
from app.models.worker_lease import WorkerLease
from app.services.worker_lease import LeaseService, get_lease_status
from app.utils.datetime_utils import utcnow
from app.worker import Worker

TTL = 90


@pytest.fixture
async def maker(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    m = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(worker_module, "async_session_maker", m)
    yield m
    await engine.dispose()


async def _age_heartbeat(maker, seconds: int) -> None:
    async with maker() as db:
        row = await db.get(WorkerLease, "sync")
        row.heartbeat_at = utcnow() - timedelta(seconds=seconds)
        await db.commit()


# -- LeaseService ----------------------------------------------------------


@pytest.mark.asyncio
async def test_first_acquire_creates_and_holds(maker):
    async with maker() as db:
        assert await LeaseService(db).try_acquire("w1", TTL) == (True, True)
    async with maker() as db:
        # Re-acquire by the same owner is a renewal, not a takeover.
        assert await LeaseService(db).try_acquire("w1", TTL) == (True, False)
        status = await get_lease_status(db, TTL)
    assert status["held"] is True and status["owner"] == "w1"


@pytest.mark.asyncio
async def test_second_worker_is_denied_while_heartbeat_fresh(maker):
    async with maker() as db:
        await LeaseService(db).try_acquire("w1", TTL)
    async with maker() as db:
        assert await LeaseService(db).try_acquire("w2", TTL) == (False, False)


@pytest.mark.asyncio
async def test_stale_heartbeat_allows_takeover(maker):
    async with maker() as db:
        await LeaseService(db).try_acquire("w1", TTL)
    await _age_heartbeat(maker, TTL + 5)
    async with maker() as db:
        assert await LeaseService(db).try_acquire("w2", TTL) == (True, True)
    async with maker() as db:
        # The old holder is now the outsider.
        assert await LeaseService(db).try_acquire("w1", TTL) == (False, False)
        assert await LeaseService(db).heartbeat("w1") is False
        assert await LeaseService(db).heartbeat("w2") is True


@pytest.mark.asyncio
async def test_release_hands_over_immediately(maker):
    async with maker() as db:
        await LeaseService(db).try_acquire("w1", TTL)
        assert await LeaseService(db).release("w1") is True
        assert await LeaseService(db).release("w1") is True  # idempotent for owner
        assert await LeaseService(db).release("w2") is False
    async with maker() as db:
        assert await LeaseService(db).try_acquire("w2", TTL) == (True, True)


@pytest.mark.asyncio
async def test_status_reports_stale_lease(maker):
    async with maker() as db:
        assert (await get_lease_status(db, TTL))["held"] is False
        await LeaseService(db).try_acquire("w1", TTL)
    await _age_heartbeat(maker, TTL + 1)
    async with maker() as db:
        status = await get_lease_status(db, TTL)
    assert status["held"] is False and status["stale"] is True and status["owner"] == "w1"


# -- Worker integration ------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_without_lease_claims_nothing(maker):
    async with maker() as db:
        await LeaseService(db).try_acquire("other-worker", TTL)
        db.add(SyncJob(job_type="full", triggered_by="manual", status="pending"))
        await db.commit()

    w = Worker()
    held, _ = await w._acquire_lease()
    assert held is False
    assert w._holds_lease is False
    # The poll body is gated on the lease in _poll_forever; a standby
    # worker must leave the pending row untouched.
    async with maker() as db:
        rows = (await db.execute(select(SyncJob))).scalars().all()
    assert [r.status for r in rows] == ["pending"]


@pytest.mark.asyncio
async def test_takeover_sweeps_running_jobs_immediately(maker):
    """A `running` row that is only 2 minutes old would survive the
    normal 180-minute sweep; after a lease takeover it is provably an
    orphan and is requeued at once."""
    async with maker() as db:
        await LeaseService(db).try_acquire("dead-worker", TTL)
        db.add(SyncJob(
            job_type="full", triggered_by="scheduled", status="running",
            started_at=utcnow() - timedelta(minutes=2),
        ))
        await db.commit()
    await _age_heartbeat(maker, TTL + 5)

    w = Worker()
    held, acquired_now = await w._acquire_lease()
    assert (held, acquired_now) == (True, True)
    await w._sweep_and_requeue(timeout_minutes=0)

    async with maker() as db:
        rows = (await db.execute(select(SyncJob).order_by(SyncJob.created_at))).scalars().all()
    statuses = sorted((r.status, r.triggered_by) for r in rows)
    assert statuses == [("failed", "scheduled"), ("pending", "requeue")]


@pytest.mark.asyncio
async def test_stop_releases_lease_only_when_idle(maker):
    w = Worker()
    await w._acquire_lease()
    w._running = True
    w._job_in_progress = True
    await w.stop()
    async with maker() as db:
        assert (await get_lease_status(db, TTL))["held"] is True, "mid-job: keep the lease until TTL"

    w2 = Worker()
    w2._running = True
    await _age_heartbeat(maker, TTL + 5)
    await w2._acquire_lease()
    await w2.stop()
    async with maker() as db:
        assert (await get_lease_status(db, TTL))["held"] is False, "idle: released for the successor"
