"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
# Import models to register them with SQLAlchemy Base before init_db
from app.models import Detection, Repository, SyncJob  # noqa: F401
from app.api.routes import detections, repositories, export, compare, releases, mitre, scheduler as scheduler_routes
from app.services.scheduler import scheduler

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    # Startup
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.repos_dir.mkdir(parents=True, exist_ok=True)
    await init_db()

    # Start scheduler if enabled
    if settings.enable_scheduler:
        scheduler.start()
        logger.info(f"Scheduler started. Next sync at: {scheduler.get_next_run_time()}")
    else:
        logger.info("Scheduler disabled in configuration")

    yield

    # Shutdown
    if scheduler.is_running:
        scheduler.stop()


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
