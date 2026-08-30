"""Weekly digest + RSS feeds.

GET /api/digest                  JSON digest for the last `days`
GET /api/digest/feed.xml         RSS: new detection rules (30d)
GET /api/digest/newly-covered.xml RSS: techniques newly covered (30d)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services.digest import compute_digest, modified_rules_feed, new_rules_feed, newly_covered_feed
from app.services.repository_sync import ALL_REPOSITORY_NAMES

router = APIRouter(prefix="/digest", tags=["digest"])


def _site_url() -> str:
    # The public site, for feed links; FRONTEND_URL is the CORS origin
    # (no trailing slash by convention).
    return (getattr(settings, "frontend_url", None) or "https://detectionexplorer.io").rstrip("/")


@router.get("")
async def get_digest(
    days: int = Query(7, ge=1, le=90, description="Window in days"),
    limit: int = Query(15, ge=5, le=50, description="Cap per secondary list (newly covered, momentum)"),
    rules_limit: int = Query(300, ge=10, le=1000, description="Cap on the new / updated rule lists"),
    db: AsyncSession = Depends(get_db),
):
    return await compute_digest(db, days=days, limit=limit, rules_limit=rules_limit)


def _source_param(source: Optional[str]) -> Optional[str]:
    if source and source not in ALL_REPOSITORY_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown source: {source}")
    return source


@router.get("/feed.xml")
async def new_rules_rss(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(50, ge=5, le=200),
    source: Optional[str] = Query(None, description="Restrict to one source"),
    db: AsyncSession = Depends(get_db),
):
    xml = await new_rules_feed(db, _site_url(), days=days, limit=limit, source=_source_param(source))
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8",
                    headers={"Cache-Control": "public, max-age=1800"})


@router.get("/modified.xml")
async def modified_rules_rss(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(50, ge=5, le=200),
    source: Optional[str] = Query(None, description="Restrict to one source"),
    db: AsyncSession = Depends(get_db),
):
    xml = await modified_rules_feed(db, _site_url(), days=days, limit=limit, source=_source_param(source))
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8",
                    headers={"Cache-Control": "public, max-age=1800"})


@router.get("/newly-covered.xml")
async def newly_covered_rss(
    days: int = Query(30, ge=7, le=365),
    limit: int = Query(50, ge=5, le=200),
    db: AsyncSession = Depends(get_db),
):
    xml = await newly_covered_feed(db, _site_url(), days=days, limit=limit)
    return Response(content=xml, media_type="application/rss+xml; charset=utf-8",
                    headers={"Cache-Control": "public, max-age=1800"})
