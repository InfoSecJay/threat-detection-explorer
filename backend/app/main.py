"""FastAPI application entry point.

This process serves the HTTP API only. Long-running sync and ingestion
work runs in a separate worker process (see `app.worker`) so that it
can never block API requests. The API communicates with the worker
exclusively through the shared `sync_jobs` table in Postgres.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db

# Import models to register them with SQLAlchemy Base before init_db
from app.models import Detection, Repository, SyncJob  # noqa: F401
from app.api.routes import (
    actors,
    compare,
    detections,
    export,
    mitre,
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
    yield


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


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "app": settings.app_name}


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
