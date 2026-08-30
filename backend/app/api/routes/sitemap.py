"""sitemap.xml for the public site (served through the Vercel rewrite
/sitemap.xml -> API). Rule, technique and actor pages plus the static
ones; regenerated per corpus fingerprint."""

from __future__ import annotations

from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.services.mitre import mitre_service
from app.services.observables import OBSERVABLE_TYPES

router = APIRouter(tags=["sitemap"])

STATIC = ["/", "/detections", "/mitre", "/actors", "/actors/heatmap", "/observables", "/intel", "/digest", "/query", "/about", "/integrations"]


def _site_url() -> str:
    return (getattr(settings, "frontend_url", None) or "https://detectionexplorer.io").rstrip("/")


async def _build(db: AsyncSession) -> str:
    site = _site_url()
    rows = (await db.execute(select(Detection.id, Detection.updated_at))).all()
    await mitre_service.ensure_loaded()
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']

    def url(loc: str, lastmod=None, priority: str = "0.5") -> None:
        parts.append("<url>")
        parts.append(f"<loc>{escape(site + loc)}</loc>")
        if lastmod is not None:
            parts.append(f"<lastmod>{lastmod.date().isoformat()}</lastmod>")
        parts.append(f"<priority>{priority}</priority>")
        parts.append("</url>")

    for p in STATIC:
        url(p, priority="0.8")
    for kind in OBSERVABLE_TYPES:
        if kind != "resource":
            url(f"/observables/{kind}", priority="0.6")
    for tid, info in mitre_service.get_all_techniques().items():
        if not info.get("deprecated") and not info.get("revoked"):
            url(f"/mitre/{tid}", priority="0.6")
    for gid, g in mitre_service.get_all_groups().items():
        if not g.get("deprecated"):
            url(f"/actors/{gid}", priority="0.6")
    for sid, s in mitre_service.get_all_software().items():
        if not s.get("deprecated"):
            url(f"/actors/{sid}", priority="0.4")
    for rid, updated in rows:
        url(f"/detections/{rid}", lastmod=updated, priority="0.5")
    parts.append("</urlset>")
    return "\n".join(parts)


@router.get("/sitemap.xml")
async def sitemap(db: AsyncSession = Depends(get_db)):
    xml = await corpus_cache.get(db, ("sitemap",), lambda: _build(db))
    return Response(content=xml, media_type="application/xml; charset=utf-8",
                    headers={"Cache-Control": "public, max-age=3600"})
