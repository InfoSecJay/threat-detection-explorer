"""Disk-pressure guard (#97): the sync refuses to start, and the corpus
snapshot refuses to write, when pg_database_size nears the configured
volume. Postgres is faked through a stand-in session; the SQLite test
engine exercises the off-Postgres no-op path."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.config import settings
from app.services import scheduler as sched
from app.services import volume_guard as vg
from app.services.scheduler import run_full_sync_job


class _PostgresSession:
    """Just enough of AsyncSession for the guard: a postgresql dialect
    and an execute() that answers pg_database_size."""

    def __init__(self, size_bytes: int):
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))
        self._size = size_bytes

    async def execute(self, *_a, **_kw):
        return SimpleNamespace(scalar=lambda: self._size)


@pytest.mark.asyncio
async def test_guard_is_a_no_op_outside_postgres(db_session):
    assert await vg.database_size_bytes(db_session) is None
    assert await vg.database_over_share(db_session, 0.0) is None
    await vg.refuse_sync_if_volume_nearly_full(db_session)  # does not raise


@pytest.mark.asyncio
async def test_refuses_over_the_share_and_names_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "postgres_volume_mb", 500)
    size = int(500 * 1024 * 1024 * 0.9)
    with pytest.raises(vg.VolumeNearlyFull) as exc:
        await vg.refuse_sync_if_volume_nearly_full(_PostgresSession(size))
    msg = str(exc.value)
    assert "450MB" in msg and "85%" in msg and "POSTGRES_VOLUME_MB" in msg


@pytest.mark.asyncio
async def test_allows_under_the_share(monkeypatch):
    monkeypatch.setattr(settings, "postgres_volume_mb", 5000)
    size = int(5000 * 1024 * 1024 * 0.5)
    await vg.refuse_sync_if_volume_nearly_full(_PostgresSession(size))


def test_snapshot_stops_before_the_sync_does():
    """Snapshots are the optional writer; they must give up first."""
    assert vg.SNAPSHOT_CAP_SHARE < vg.SYNC_REFUSE_SHARE < 1.0


@pytest.mark.asyncio
async def test_sync_job_fails_cleanly_when_volume_nearly_full(db_session, monkeypatch):
    """The refusal lands on the job row as `failed` + error_message
    instead of a PANIC halfway through the corpus."""

    @asynccontextmanager
    async def one_session():
        yield db_session

    monkeypatch.setattr(sched, "async_session_maker", one_session)

    async def refuse(_db):
        raise vg.VolumeNearlyFull("Sync refused: database is 450MB, over 85% of the 500MB volume")

    monkeypatch.setattr(sched, "refuse_sync_if_volume_nearly_full", refuse)

    job = await run_full_sync_job(triggered_by="test", repository="sigma")
    assert job.status == "failed"
    assert job.error_message.startswith("Sync refused")
    assert job.error_count == 1
    assert job.rules_stored in (None, 0)
