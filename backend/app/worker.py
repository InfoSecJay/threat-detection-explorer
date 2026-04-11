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
from typing import Optional

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI

from app.config import settings
from app.database import async_session_maker, init_db
from app.services.job_queue import JobQueueService
from app.services.scheduler import run_full_sync_job

logger = logging.getLogger(__name__)

# How often to check for new pending jobs when idle. Tradeoff: lower
# numbers make manually-triggered syncs start faster but put more load
# on Postgres. 5s gives sub-10s perceived latency without being noisy.
POLL_INTERVAL_SECONDS = 5

# How long a job can stay in `running` state before the worker assumes
# the previous worker that owned it crashed and resets it to `failed`.
# Sized generously so legitimate long-running syncs (sentinel takes
# several minutes) don't get nuked.
STUCK_JOB_TIMEOUT_MINUTES = 30


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

    async def start(self) -> None:
        """Initialize the worker and enter the main poll loop."""
        await init_db()
        settings.repos_dir.mkdir(parents=True, exist_ok=True)

        # Sweep any stuck jobs from a previous worker that crashed mid-run.
        # Doing this once at startup is enough because we only run one
        # worker and jobs never become stuck while we're alive.
        async with async_session_maker() as db:
            queue = JobQueueService(db)
            reset_count = await queue.reset_stuck_jobs(
                timeout_minutes=STUCK_JOB_TIMEOUT_MINUTES
            )
            if reset_count > 0:
                logger.warning(
                    f"Reset {reset_count} stuck job(s) from a previous worker run"
                )

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
                ),
                id="daily_full_sync",
                name="Daily Full Sync",
                replace_existing=True,
            )
            self._scheduler.start()
            logger.info(
                f"Nightly sync scheduled for "
                f"{settings.sync_schedule_hour:02d}:"
                f"{settings.sync_schedule_minute:02d} UTC"
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
            self._health_server.serve(),
        )

    async def _poll_forever(self) -> None:
        """Main poll loop. Runs until `self._running` is set to False."""
        while self._running:
            try:
                await self._poll_once()
            except Exception as e:
                # Never let an exception from one job kill the poll loop.
                # Log loudly and keep polling.
                logger.error(f"Poll loop error: {e}", exc_info=True)

            if self._running:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)

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
