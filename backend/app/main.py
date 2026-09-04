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
from fastapi.responses import JSONResponse, RedirectResponse

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


API_DESCRIPTION = """
Read-only REST API behind [detectionexplorer.io](https://detectionexplorer.io):
15,000+ open-source detection rules from thirteen repositories, normalized
into one schema, mapped to MITRE ATT&CK, with the observables each rule
keys on. No authentication.

**Base URL:** `https://detectionexplorer.io/api/v1`

### Versioning and deprecation
- Paths are versioned. `/api/v1` is the current version; the unversioned
  `/api/<path>` form is a permanent alias of the current version and will
  keep resolving for as long as v1 exists.
- Additive changes (new endpoints, new optional fields, new enum values in
  facets as the corpus grows) ship without a version bump.
- Vocabulary changes are documented here. 2026-09: `platforms` was split
  into `platforms` (OS only), `domains` (attack surface) and `products`
  (vendor / application); a `platforms=` filter using a pre-split value
  such as `okta` is re-targeted at the field that holds it now.
- Breaking changes ship as `/api/v2` with v1 kept for at least six months.
  Deprecations are announced in the repository release notes and on a
  GitHub issue labelled `api` at least 30 days ahead.

### Fair use
- Rate limit at the edge: **40 requests per 10 seconds per IP** on `/api/*`.
  Over that you get `429 Too Many Requests` with `Retry-After`.
- Read responses are edge-cached for 15 minutes and purged after the
  nightly sync (02:00 America/Toronto), so polling faster than that
  returns the same data.
- Need the whole corpus? Use the export endpoints once rather than paging
  the list endpoint, or open an issue and ask for a bulk dump.
- No SLA; hosted on Railway behind Cloudflare and Vercel. `/api/health`
  answers 503 when the database is unreachable.

### Data and licensing
Every rule stays under its upstream license, shown on each rule page and in
the `source_repo_url` / `license` fields. The normalization, this API and
its schema are Apache-2.0
([repository](https://github.com/InfoSecJay/threat-detection-explorer)).

### Worked examples and contributing
Copy-paste workflows (weekly digest to Slack, a Navigator layer per actor,
diffing your own rule set against the corpus) live in
[docs/api-examples.md](https://github.com/InfoSecJay/threat-detection-explorer/blob/master/docs/api-examples.md).
Missing a source? Use the
[suggest-a-source template](https://github.com/InfoSecJay/threat-detection-explorer/issues/new?template=suggest-a-source.md).
An MCP server for this API is tracked in
[#92](https://github.com/InfoSecJay/threat-detection-explorer/issues/92).
"""

app = FastAPI(
    title=settings.app_name,
    description=API_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    # Docs live under /api so the apex proxy (vercel.json rewrites /api/*)
    # serves them at detectionexplorer.io/api/docs (#92 / S4.8).
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
    servers=[{"url": settings.frontend_url, "description": "Production"}] if settings.frontend_url else None,
)


@app.get("/docs", include_in_schema=False)
async def _legacy_docs():
    return RedirectResponse("/api/docs", status_code=301)


@app.get("/openapi.json", include_in_schema=False)
async def _legacy_openapi():
    return RedirectResponse("/api/openapi.json", status_code=301)

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
_CACHEABLE_PREFIXES = tuple(
    f"{settings.api_prefix}{p}" for p in (
        "/detections", "/mitre", "/actors", "/trending", "/observables",
        "/digest", "/compare", "/query", "/search", "/methodology",
        "/event-ids", "/export",
    )
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


# ── Unversioned alias (#92 / S4.8) ─────────────────────────────────────
# Routers mount at settings.api_prefix (/api/v1). Everything that ever
# called /api/<path> -- the frontend before it moved, vercel.json
# rewrites, RSS readers, scripts in the wild -- keeps working: the ASGI
# scope path is rewritten before routing, so the spec stays single and
# the edge cache key is whatever the caller asked for. Health and the
# docs are intentionally unversioned and stay where they are.
_UNVERSIONED = ("/api/health", "/api/docs", "/api/openapi.json")


class LegacyPrefixAlias:
    def __init__(self, asgi_app, legacy: str = "/api", canonical: str = settings.api_prefix):
        self.app = asgi_app
        self.legacy = legacy.rstrip("/")
        self.canonical = canonical.rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if (
                self.legacy != self.canonical
                and path.startswith(self.legacy + "/")
                and not path.startswith(self.canonical + "/")
                and path != self.canonical
                and not path.startswith(_UNVERSIONED)
            ):
                new_path = self.canonical + path[len(self.legacy):]
                scope = dict(scope)
                scope["path"] = new_path
                scope["raw_path"] = new_path.encode("utf-8")
        await self.app(scope, receive, send)


app.add_middleware(LegacyPrefixAlias)
