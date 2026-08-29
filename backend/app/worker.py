"""Detection Explorer background worker.

This module is the entrypoint for the Railway worker service. It runs in
its own process (separate Railway service) from the FastAPI API so that
long-running git clones and rule ingestion never block API requests.

Three responsibilities:

1. Poll the `sync_jobs` table for pending jobs and process them one at a
   time via `app.services.scheduler.run_full_sync_job`.

2. Host the APScheduler cron job for the nightly full sync. The cron
   fires a callback that inserts a new pending job row; the poll loop
   then picks it up like any other job, so scheduled and manual syncs
   go through identical code paths.

3. Serve a tiny /api/health endpoint so Railway's deployment healthcheck
   passes. Without this, Railway fails the deploy after ~100 seconds of
   "service unavailable" because the worker has no HTTP listener. The
   health endpoint is served on the same asyncio loop as the poll loop.

Run locally with:

    python -m app.worker

Run in production via the Procfile `worker` dyno or Railway's "Start
Command" override on the worker service.
"""

import asyncio
import logging
import os
import signal
import socket
import uuid
from datetime import datetime

from app.utils.datetime_utils import utcnow
from typing import Optional

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI

from app.config import settings
from app.database import async_session_maker, init_db
from app.services.github_auth import check_github_token, log_token_status
from app.services.job_queue import JobQueueService
from app.services.scheduler import run_full_sync_job
from app.services.worker_lease import LeaseService

logger = logging.getLogger(__name__)

# How often to check for new pending jobs when idle. Tradeoff: lower
# numbers make manually-triggered syncs start faster but put more load
# on Postgres. 5s gives sub-10s perceived latency without being noisy.
POLL_INTERVAL_SECONDS = 5

# How long a job can stay in `running` state before the worker assumes
# the previous worker that owned it crashed and resets it to `failed`.
# Sized generously so legitimate long-running syncs can complete —
# sentinel ingest alone is ~25 minutes. Must be comfortably larger than
# the slowest legitimate sync-step so we never nuke work in progress.
STUCK_JOB_TIMEOUT_MINUTES = 180

# How often to re-run the stuck-job sweep inside the poll loop. The
# original design only ran it at worker startup, but that misses a bad
# race: if a deploy kills the worker mid-job and the new worker comes
# up before `STUCK_JOB_TIMEOUT_MINUTES` has elapsed, the stuck row sits
# as `running` forever with no one to clean it up. Sweeping periodically
# fixes this — worst case the orphan lives for `SWEEP + TIMEOUT` minutes.
STUCK_JOB_SWEEP_INTERVAL_SECONDS = 300  # 5 min

# Single-flight lease (#36). Only the holder claims jobs; a lease whose
# heartbeat is older than the TTL belongs to a dead worker and is taken
# over. Heartbeats run on their own task so a long ingest does not let
# the lease lapse. 90s TTL / 20s beat tolerates a slow DB round-trip
# or a GC pause without a false takeover.
LEASE_TTL_SECONDS = 90
LEASE_HEARTBEAT_INTERVAL_SECONDS = 20
LEASE_STANDBY_LOG_INTERVAL_SECONDS = 300


def _build_health_app() -> FastAPI:
    """Build a minimal FastAPI app that serves `/api/health` only.

    This exists solely to satisfy Railway's deployment healthcheck,
    which is configured in `backend/railway.toml` to hit `/api/health`.
    Without it, the worker deploy is marked failed after ~100s of
    retries because the worker has no HTTP listener of its own.

    Responding successfully here is also a real liveness signal: if
    the asyncio event loop is wedged or the process crashed, Railway
    will fail the healthcheck and auto-restart the container via the
    on_failure restart policy, which is exactly what we want.
    """
    app = FastAPI(title="Detection Explorer Worker", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy", "service": "threat-detection-explorer-worker"}

    return app


class Worker:
    """Worker process: poll loop + cron scheduler + health HTTP server.

    The worker is a long-lived asyncio program. `start()` blocks until
    the worker is asked to stop via SIGTERM/SIGINT or an internal error.
    The health server and poll loop run concurrently on the same event
    loop via asyncio.gather so they share the same lifecycle.
    """

    def __init__(self) -> None:
        self._running: bool = False
        self._scheduler: Optional[AsyncIOScheduler] = None
        self._health_server: Optional[uvicorn.Server] = None
        # Monotonic wall-clock of the last stuck-job sweep. Start at
        # "never" so the first poll cycle after startup still triggers
        # a sweep (in addition to the one at startup) — the startup
        # sweep runs BEFORE any jobs are claimed, but a deploy-time
        # race means a fresh orphan can land between startup and now.
        self._last_sweep_at: Optional[datetime] = None
        # Lease identity + state (#36). The id is informational (shows
        # who holds the lease in the table); uniqueness comes from the
        # nonce so two containers on one host never collide.
        self._worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self._holds_lease = False
        self._job_in_progress = False
        self._standby_logged_at: Optional[datetime] = None

    async def start(self) -> None:
        """Initialize the worker and enter the main poll loop."""
        await init_db()
        settings.repos_dir.mkdir(parents=True, exist_ok=True)

        # Probe GITHUB_TOKEN once per boot (#46). An expired PAT becomes
        # an ERROR with its expiry date at startup, instead of N per-repo
        # warnings buried at the end of each nightly sync. Never blocks
        # startup -- the worker's job is ingestion, which is anonymous.
        try:
            log_token_status(await check_github_token())
        except Exception as e:
            logger.warning(f"GITHUB_TOKEN startup check raised: {e}")

        # Stuck-job sweeping now happens from the poll loop once this
        # worker holds the sync lease (#36): sweeping before we know
        # whether another worker is alive could reset ITS running job.

        # Start the nightly cron in-process. This is safe because this
        # worker has no HTTP workload to block — the whole point is that
        # it's isolated from the API.
        if settings.enable_scheduler:
            self._scheduler = AsyncIOScheduler()
            self._scheduler.add_job(
                self._enqueue_scheduled_sync,
                CronTrigger(
                    hour=settings.sync_schedule_hour,
                    minute=settings.sync_schedule_minute,
                    timezone=settings.sync_schedule_timezone,
                ),
                id="daily_full_sync",
                name="Daily Full Sync",
                replace_existing=True,
            )
            self._scheduler.start()
            logger.info(
                f"Nightly sync scheduled for "
                f"{settings.sync_schedule_hour:02d}:"
                f"{settings.sync_schedule_minute:02d} "
                f"{settings.sync_schedule_timezone}"
            )
        else:
            logger.info("Scheduler disabled via ENABLE_SCHEDULER=false")

        # Install graceful shutdown handlers. On Windows, signal handlers
        # behave a little differently but SIGINT (Ctrl+C) still works via
        # KeyboardInterrupt in the main loop.
        self._running = True
        loop = asyncio.get_running_loop()
        for sig_name in ("SIGTERM", "SIGINT"):
            sig = getattr(signal, sig_name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(
                    sig, lambda: asyncio.create_task(self.stop())
                )
            except NotImplementedError:
                # Windows asyncio loop doesn't support add_signal_handler.
                # KeyboardInterrupt will still work as a fallback in main().
                pass

        # Configure the health HTTP server. Railway injects PORT for
        # services with healthchecks; default to 8080 locally.
        port = int(os.environ.get("PORT", "8080"))
        health_config = uvicorn.Config(
            _build_health_app(),
            host="0.0.0.0",
            port=port,
            log_level="warning",
            access_log=False,
        )
        self._health_server = uvicorn.Server(health_config)
        logger.info(f"Worker started — polling for pending jobs (health on :{port})")

        # Run poll loop and health server concurrently on the same event loop.
        # asyncio.gather will raise if either coroutine raises, so wrap the
        # poll loop in try/except inside _poll_forever to keep it alive.
        await asyncio.gather(
            self._poll_forever(),
            self._heartbeat_forever(),
            self._health_server.serve(),
        )

    async def _poll_forever(self) -> None:
        """Main poll loop. Runs until `self._running` is set to False."""
        while self._running:
            try:
                held, acquired_now = await self._acquire_lease()
                if held:
                    if acquired_now:
                        # Every `running` row belongs to a holder that is
                        # gone (we would not have the lease otherwise), so
                        # requeue the lost work now rather than after the
                        # 180-minute stuck timeout -- the 3h-per-deploy
                        # cost that #36 was opened for.
                        await self._sweep_and_requeue(timeout_minutes=0)
                        self._last_sweep_at = utcnow()
                    await self._maybe_sweep_stuck_jobs()
                    await self._poll_once()
                else:
                    self._log_standby()
            except Exception as e:
                # Never let an exception from one job kill the poll loop.
                # Log loudly and keep polling.
                logger.error(f"Poll loop error: {e}", exc_info=True)

            if self._running:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def _acquire_lease(self) -> tuple[bool, bool]:
        async with async_session_maker() as db:
            held, acquired_now = await LeaseService(db).try_acquire(
                self._worker_id, LEASE_TTL_SECONDS,
            )
        if held and not self._holds_lease:
            logger.info(f"Holding sync lease as {self._worker_id}")
        if not held and self._holds_lease:
            logger.error(
                f"Lost sync lease ({self._worker_id}); standing by. A job in "
                f"progress will finish but no new jobs are claimed."
            )
        self._holds_lease = held
        return held, acquired_now

    def _log_standby(self) -> None:
        now = utcnow()
        if (
            self._standby_logged_at is None
            or (now - self._standby_logged_at).total_seconds() >= LEASE_STANDBY_LOG_INTERVAL_SECONDS
        ):
            logger.info(
                f"Sync lease held by another worker; {self._worker_id} standing by "
                f"(takeover after {LEASE_TTL_SECONDS}s without a heartbeat)"
            )
            self._standby_logged_at = now

    async def _heartbeat_forever(self) -> None:
        """Renew the lease on its own task so a multi-hour ingest cannot
        let it lapse. Silent when we do not hold it."""
        while self._running:
            await asyncio.sleep(LEASE_HEARTBEAT_INTERVAL_SECONDS)
            if not self._holds_lease:
                continue
            try:
                async with async_session_maker() as db:
                    still_ours = await LeaseService(db).heartbeat(self._worker_id)
                if not still_ours:
                    logger.error(f"Heartbeat rejected: {self._worker_id} no longer owns the sync lease")
                    self._holds_lease = False
            except Exception as e:
                logger.warning(f"Lease heartbeat failed: {e}")

    async def _maybe_sweep_stuck_jobs(self) -> None:
        """Re-run the stuck-job sweep every SWEEP_INTERVAL seconds.

        The startup sweep catches jobs left over from a previous worker
        that died, but it only runs once. If Railway deploys a new image
        WHILE a job is running, the old worker is killed mid-job and the
        new worker comes up before `STUCK_JOB_TIMEOUT_MINUTES` has
        elapsed — so the startup sweep finds nothing and the orphan
        sits forever. Running the sweep periodically from the poll
        loop closes that window.
        """
        now = utcnow()
        if (
            self._last_sweep_at is not None
            and (now - self._last_sweep_at).total_seconds()
            < STUCK_JOB_SWEEP_INTERVAL_SECONDS
        ):
            return
        await self._sweep_and_requeue()
        self._last_sweep_at = now

    async def _sweep_and_requeue(
        self, timeout_minutes: int = STUCK_JOB_TIMEOUT_MINUTES,
    ) -> None:
        """Reset stuck jobs, then requeue the lost work.

        `timeout_minutes=0` is the lease-takeover case: the previous
        holder is provably gone, so every `running` row is an orphan.

        A stuck `running` row almost always means a Railway redeploy (or
        OOM) killed the previous worker mid-sync. Marking it failed is
        bookkeeping; the important part is that the night's sync still
        has to happen — three of the four nightly runs Aug 9-12 2026
        were lost this way and simply never ran, which left sources
        visibly stale on the Integrations page.

        Each swept job is re-inserted as a fresh pending row with
        `triggered_by="requeue"`. A swept row that was ITSELF a requeue
        is not requeued again — if the job dies twice in a row we assume
        the job itself is crashing the worker and stop retrying rather
        than clone-looping forever.
        """
        async with async_session_maker() as db:
            queue = JobQueueService(db)
            swept = await queue.reset_stuck_jobs(timeout_minutes=timeout_minutes)
            for job in swept:
                if job["triggered_by"] == "requeue":
                    logger.error(
                        f"Stuck job {job['id'][:8]} was already a requeue "
                        f"and died again — NOT requeuing (possible "
                        f"job-induced crash loop)"
                    )
                    continue
                new_job = await queue.create_pending_job(
                    job_type=job["job_type"],
                    repository=job["repository"],
                    triggered_by="requeue",
                )
                logger.warning(
                    f"Stuck job {job['id'][:8]} (trigger={job['triggered_by']}, "
                    f"repo={job['repository'] or 'ALL'}) reset and requeued "
                    f"as {new_job.id[:8]}"
                )

    async def stop(self) -> None:
        """Request graceful shutdown of the poll loop and health server."""
        if not self._running:
            return
        logger.info("Worker stopping...")
        self._running = False
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)
        if self._health_server is not None:
            self._health_server.should_exit = True
        # Hand the lease over immediately so the replacement container
        # starts claiming within one poll -- UNLESS a job is mid-flight:
        # then we keep it until the TTL lapses, so the successor cannot
        # start a second sync on the shared volume while this one is
        # still being torn down (the deploy-overlap race in #36).
        if self._holds_lease and not self._job_in_progress:
            try:
                async with async_session_maker() as db:
                    await LeaseService(db).release(self._worker_id)
                logger.info("Released sync lease")
            except Exception as e:
                logger.warning(f"Lease release failed (TTL will expire it): {e}")
            self._holds_lease = False

    async def _enqueue_scheduled_sync(self) -> None:
        """APScheduler callback: queue a nightly full sync job.

        This does NOT run the sync itself — it only inserts a pending job
        row. The poll loop claims and processes it like any other job, so
        scheduled and manual syncs share the same code path.
        """
        async with async_session_maker() as db:
            queue = JobQueueService(db)
            job = await queue.create_pending_job(
                job_type="full",
                repository=None,
                triggered_by="scheduled",
            )
            logger.info(f"Nightly sync enqueued as job {job.id[:8]}")

    async def _poll_once(self) -> None:
        """Try to claim one pending job and run it to completion."""
        async with async_session_maker() as db:
            queue = JobQueueService(db)
            job = await queue.claim_next_pending()

        if job is None:
            return

        logger.info(
            f"Claimed job {job.id[:8]} "
            f"(type={job.job_type}, repo={job.repository or 'ALL'}, "
            f"trigger={job.triggered_by})"
        )

        self._job_in_progress = True
        try:
            await run_full_sync_job(
                triggered_by=job.triggered_by,
                repository=job.repository,
                job_id=job.id,
            )
            logger.info(f"Job {job.id[:8]} finished")
        except Exception as e:
            # run_full_sync_job already marks the row failed internally,
            # but if it blows up before that (e.g. exception in setup),
            # make sure the row doesn't stay in `running` forever.
            logger.error(f"Job {job.id[:8]} crashed: {e}", exc_info=True)
            async with async_session_maker() as db:
                queue = JobQueueService(db)
                await queue.mark_failed(job.id, f"{type(e).__name__}: {e}")
        finally:
            self._job_in_progress = False


async def main() -> None:
    """Worker program entry point. Configures logging and runs forever."""
    logging.basicConfig(
        level=logging.DEBUG if settings.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    worker = Worker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()
    logger.info("Worker shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
