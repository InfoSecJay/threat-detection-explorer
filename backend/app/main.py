"""FastAPI application entry point.

This process serves the HTTP API only. Long-running sync and ingestion
work runs in a separate worker process (see `app.worker`) so that it
can never block API requests. The API communicates with the worker
exclusively through the shared `sync_jobs` table in Postgres.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import get_db, init_db
from app.services.corpus_cache import corpus_cache
from app.services.warmup import warm_caches_background

# Import models to register them with SQLAlchemy Base before init_db
from app.models import Detection, Repository, SyncJob  # noqa: F401
from app.api.routes import (
    actors,
    compare,
    detections,
    digest,
    export,
    methodology,
    mitre,
    observables,
    og,
    prerender,
    sitemap,
    query,
    releases,
    repositories,
    scheduler as scheduler_routes,
    trending,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    # repos_dir is owned by the worker service and never read from here,
    # but we create it defensively so local dev (single process) works.
    settings.repos_dir.mkdir(parents=True, exist_ok=True)
    await init_db()
    logger.info(
        "API process started. Sync scheduling and processing live in the "
        "worker service."
    )
    warm_task = None
    if settings.warm_caches_on_start:
        # Fire-and-forget; the task owns its session and error boundary.
        warm_task = asyncio.create_task(warm_caches_background(), name="cache-warmup")
    yield
    if warm_task is not None and not warm_task.done():
        warm_task.cancel()


app = FastAPI(
    title=settings.app_name,
    description="API for exploring and comparing security detection rules across vendors",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Unhandled exceptions bypass CORSMiddleware (Starlette's
# ServerErrorMiddleware sits outside it), so a bare 500 reaches the
# browser without CORS headers and surfaces as an opaque "Network
# Error" in the frontend. This handler logs the traceback and mirrors
# the CORS headers so the FE can render a real error message.
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception(
        "Unhandled error on %s %s", request.method, request.url.path
    )
    headers = {}
    origin = request.headers.get("origin")
    if origin and origin in settings.cors_origins:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
        headers=headers,
    )


@app.get("/api/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check with what is running: the deployed commit (Railway
    exposes it) and the corpus stamp the caches key on.

    The corpus stamp is a real query, and its failure is the answer:
    during the 2026-08-31 outage (#97) every data route 500ed for five
    hours while this endpoint stayed green because it never touched the
    database. A 503 here is what an uptime monitor can key on.
    """
    try:
        count, latest = await corpus_cache.fingerprint(db)
        database = "ok"
    except Exception as e:  # noqa: BLE001 -- health must answer even if the DB is out
        count, latest = None, None
        database = f"unreachable: {type(e).__name__}"
    body = {
        "status": "healthy" if database == "ok" else "degraded",
        "app": settings.app_name,
        "commit": (os.environ.get("RAILWAY_GIT_COMMIT_SHA") or os.environ.get("GIT_COMMIT_SHA") or "")[:12] or None,
        "database": database,
        "corpus": {"rules": count, "updated_at": latest},
    }
    # Never edge-cached: an uptime probe must see the live answer.
    headers = {"Cache-Control": "no-store"}
    if database != "ok":
        return JSONResponse(status_code=503, content=body, headers=headers)
    return JSONResponse(content=body, headers=headers)


# Include routers
app.include_router(repositories.router, prefix=settings.api_prefix)
app.include_router(detections.router, prefix=settings.api_prefix)
app.include_router(export.router, prefix=settings.api_prefix)
app.include_router(compare.router, prefix=settings.api_prefix)
app.include_router(releases.router, prefix=settings.api_prefix)
app.include_router(mitre.router, prefix=settings.api_prefix)
app.include_router(scheduler_routes.router, prefix=settings.api_prefix)
app.include_router(trending.router, prefix=settings.api_prefix)
app.include_router(actors.router, prefix=settings.api_prefix)
app.include_router(actors.software_router, prefix=settings.api_prefix)
app.include_router(query.router, prefix=settings.api_prefix)
app.include_router(methodology.router, prefix=settings.api_prefix)
app.include_router(digest.router, prefix=settings.api_prefix)
app.include_router(observables.router, prefix=settings.api_prefix)
app.include_router(sitemap.router, prefix=settings.api_prefix)
app.include_router(prerender.router, prefix=settings.api_prefix)
app.include_router(og.router, prefix=settings.api_prefix)


# Read routes are cacheable at the edge: the corpus changes once a day
# (teardown F06 / #80). Set only where the handler did not choose its
# own policy. Cloudflare/Vercel honour s-maxage; browsers ignore it.
_CACHEABLE_PREFIXES = (
    "/api/detections", "/api/mitre", "/api/actors", "/api/trending",
    "/api/observables", "/api/digest", "/api/compare", "/api/query",
    "/api/search", "/api/methodology", "/api/event-ids", "/api/export",
)


@app.middleware("http")
async def edge_cache_headers(request, call_next):
    response = await call_next(request)
    if (
        request.method == "GET"
        and response.status_code == 200
        and request.url.path.startswith(_CACHEABLE_PREFIXES)
        and "cache-control" not in response.headers
    ):
        response.headers["Cache-Control"] = "public, s-maxage=900, stale-while-revalidate=86400"
    return response
