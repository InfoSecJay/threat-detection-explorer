"""Sitemaps for the public site (served through the Vercel rewrites
/sitemap.xml and /sitemap-<section>.xml -> API).

/sitemap.xml is a sitemap INDEX pointing at one file per content type
(teardown E5 / #123) -- pages, mitre, actors, detections -- so Search
Console reports indexing coverage per section and a detail-page
failure (the prerender class of bug, R03) shows up as "detections"
dropping, not as noise in one 17k-URL file. Each section regenerates
per corpus fingerprint.
"""

from __future__ import annotations

from typing import Callable
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.services.mitre import mitre_service
from app.services.observables import OBSERVABLE_TYPES

router = APIRouter(tags=["sitemap"])

STATIC = ["/", "/detections", "/mitre", "/actors", "/actors/heatmap", "/observables", "/intel", "/digest", "/query", "/about", "/integrations"]

_XML_HEADERS = {"Cache-Control": "public, max-age=3600"}


def _site_url() -> str:
    return (getattr(settings, "frontend_url", None) or "https://detectionexplorer.io").rstrip("/")


class _UrlSet:
    def __init__(self) -> None:
        self.site = _site_url()
        self.parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']

    def url(self, loc: str, lastmod=None, priority: str = "0.5") -> None:
        self.parts.append("<url>")
        self.parts.append(f"<loc>{escape(self.site + loc)}</loc>")
        if lastmod is not None:
            self.parts.append(f"<lastmod>{lastmod.date().isoformat()}</lastmod>")
        self.parts.append(f"<priority>{priority}</priority>")
        self.parts.append("</url>")

    def render(self) -> str:
        return "\n".join(self.parts + ["</urlset>"])


async def _pages(db: AsyncSession) -> str:
    s = _UrlSet()
    for p in STATIC:
        s.url(p, priority="0.8")
    for kind in OBSERVABLE_TYPES:
        if kind != "resource":
            s.url(f"/observables/{kind}", priority="0.6")
    return s.render()


async def _mitre(db: AsyncSession) -> str:
    await mitre_service.ensure_loaded()
    s = _UrlSet()
    for tid, info in mitre_service.get_all_techniques().items():
        if not info.get("deprecated") and not info.get("revoked"):
            s.url(f"/mitre/{tid}", priority="0.6")
    return s.render()


async def _actors(db: AsyncSession) -> str:
    await mitre_service.ensure_loaded()
    s = _UrlSet()
    for gid, g in mitre_service.get_all_groups().items():
        if not g.get("deprecated"):
            s.url(f"/actors/{gid}", priority="0.6")
    for sid, sw in mitre_service.get_all_software().items():
        if not sw.get("deprecated"):
            s.url(f"/actors/{sid}", priority="0.4")
    return s.render()


async def _detections(db: AsyncSession) -> str:
    rows = (await db.execute(select(Detection.id, Detection.updated_at))).all()
    s = _UrlSet()
    for rid, updated in rows:
        s.url(f"/detections/{rid}", lastmod=updated, priority="0.5")
    return s.render()


SECTIONS: dict[str, Callable] = {
    "pages": _pages,
    "mitre": _mitre,
    "actors": _actors,
    "detections": _detections,
}


async def _index(db: AsyncSession) -> str:
    site = _site_url()
    # lastmod on the index = newest rule change; the other sections move
    # with ATT&CK releases, which the corpus fingerprint also tracks.
    newest = (await db.execute(select(func.max(Detection.updated_at)))).scalar()
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for name in SECTIONS:
        parts.append("<sitemap>")
        parts.append(f"<loc>{escape(site)}/sitemap-{name}.xml</loc>")
        if newest is not None:
            parts.append(f"<lastmod>{newest.date().isoformat()}</lastmod>")
        parts.append("</sitemap>")
    parts.append("</sitemapindex>")
    return "\n".join(parts)


def _xml(content: str) -> Response:
    return Response(content=content, media_type="application/xml; charset=utf-8", headers=_XML_HEADERS)


@router.get("/sitemap.xml")
async def sitemap_index(db: AsyncSession = Depends(get_db)):
    return _xml(await corpus_cache.get(db, ("sitemap", "index"), lambda: _index(db), persist=True))


@router.get("/sitemap-{section}.xml")
async def sitemap_section(section: str, db: AsyncSession = Depends(get_db)):
    build = SECTIONS.get(section)
    if build is None:
        raise HTTPException(status_code=404, detail=f"no sitemap section '{section}'")
    return _xml(await corpus_cache.get(db, ("sitemap", section), lambda: build(db), persist=True))
