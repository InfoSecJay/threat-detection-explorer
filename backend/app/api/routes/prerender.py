"""Bot-facing prerendered pages (#76 / teardown F01+F02).

The SPA serves an identical shell for every route, so crawlers and
link unfurlers (Slack, LinkedIn, Discord, Google) see nothing. Vercel
rewrites route requests whose User-Agent matches known bots to these
endpoints, which return small server-rendered HTML documents with full
Open Graph / Twitter Card / canonical metadata and the page's actual
content. Humans keep getting the SPA.

Kept deliberately simple: no styling beyond honest content -- the
audience is a parser, and readable HTML is also the correct fallback
for a human who somehow lands here (every page links its canonical
URL).
"""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.mitre import mitre_service

router = APIRouter(prefix="/prerender", tags=["prerender"])

SITE = "Detection Explorer"
ORIGIN = "https://detectionexplorer.io"


def _page(
    title: str,
    description: str,
    canonical_path: str,
    image_path: str,
    body: str,
    og_type: str = "article",
) -> HTMLResponse:
    t = escape(f"{title} · {SITE}" if title != SITE else SITE)
    d = escape((description or "").strip().replace("\n", " ")[:300])
    canonical = f"{ORIGIN}{canonical_path}"
    image = f"{ORIGIN}{image_path}"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{t}</title>
<meta name="description" content="{d}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{t}">
<meta property="og:description" content="{d}">
<meta property="og:url" content="{canonical}">
<meta property="og:type" content="{og_type}">
<meta property="og:site_name" content="{SITE}">
<meta property="og:image" content="{image}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
<meta name="twitter:image" content="{image}">
</head>
<body>
{body}
<p><a href="{canonical}">Open in {escape(SITE)}</a></p>
</body>
</html>"""
    return HTMLResponse(
        content=html,
        headers={"Cache-Control": "public, s-maxage=3600, stale-while-revalidate=86400"},
    )


def _kv(label: str, value: str) -> str:
    return f"<li><strong>{escape(label)}:</strong> {escape(value)}</li>"


@router.get("/detection/{detection_id}", response_class=HTMLResponse)
async def prerender_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    from app.services.detection_resolver import resolve_detection

    d, _via_alias = await resolve_detection(db, detection_id)
    if d is None:
        return HTMLResponse(status_code=404, content="<h1>Rule not found</h1>")
    techniques = [t for t in (d.mitre_techniques or []) if isinstance(t, str)]
    tech_html = " ".join(
        f'<a href="{ORIGIN}/mitre/{escape(t)}">{escape(t)}</a>' for t in techniques[:10]
    )
    facts = "".join([
        _kv("Source", d.source),
        _kv("Language", d.language or ""),
        _kv("Severity", d.severity or ""),
        _kv("Status", d.status or ""),
    ])
    query = escape((d.detection_logic or "")[:4000])
    body = f"""<h1>{escape(d.title)}</h1>
<p>{escape((d.description or "")[:1200])}</p>
<ul>{facts}</ul>
<p>ATT&amp;CK: {tech_html or "unmapped"}</p>
<h2>Detection logic</h2>
<pre>{query}</pre>"""
    desc = d.description or f"{d.source} detection rule"
    return _page(d.title, desc, f"/detections/{d.id}", f"/api/og/detection/{d.id}.png", body)


@router.get("/technique/{technique_id}", response_class=HTMLResponse)
async def prerender_technique(technique_id: str):
    await mitre_service.ensure_loaded()
    tid = technique_id.upper()
    info = mitre_service.get_technique(tid)
    if not info:
        return HTMLResponse(status_code=404, content="<h1>Technique not found</h1>")
    name = info.get("name", tid)
    desc = (info.get("description") or "").strip()
    body = f"""<h1>{escape(tid)} — {escape(name)}</h1>
<p>{escape(desc[:1200])}</p>
<p>Cross-vendor detection rules for this ATT&amp;CK technique, normalized from thirteen open-source repositories.</p>"""
    return _page(
        f"{tid} {name}",
        desc or f"Detection rules for ATT&CK technique {tid}",
        f"/mitre/{tid}",
        f"/api/og/technique/{tid}.png",
        body,
    )


@router.get("/actor/{actor_id}", response_class=HTMLResponse)
async def prerender_actor(actor_id: str):
    await mitre_service.ensure_loaded()
    aid = actor_id.upper()
    info = mitre_service.get_all_groups().get(aid) or mitre_service.get_all_software().get(aid)
    if not info:
        return HTMLResponse(status_code=404, content="<h1>Actor not found</h1>")
    name = info.get("name", aid)
    aliases = ", ".join(info.get("aliases", [])[:8])
    desc = (info.get("description") or "").strip()
    body = f"""<h1>{escape(name)} ({escape(aid)})</h1>
{f"<p><strong>Aliases:</strong> {escape(aliases)}</p>" if aliases else ""}
<p>{escape(desc[:1200])}</p>
<p>Which of this adversary's ATT&amp;CK techniques have public detection rules -- and which have none.</p>"""
    return _page(
        f"{name} ({aid})",
        desc or f"Detection coverage for {name}",
        f"/actors/{aid}",
        f"/api/og/actor/{aid}.png",
        body,
        og_type="profile",
    )


@router.get("/home", response_class=HTMLResponse)
async def prerender_home(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(Detection))).scalar() or 0
    desc = (
        f"{total:,} open-source detection rules from thirteen repositories -- Sigma, Elastic, Splunk, "
        "Sentinel, Panther, Sublime and more -- normalized into one schema, mapped to MITRE ATT&CK, "
        "with the observables each rule keys on."
    )
    body = f"""<h1>{escape(SITE)}</h1>
<p>{escape(desc)}</p>
<ul>
<li><a href="{ORIGIN}/detections">Search {total:,} detection rules</a></li>
<li><a href="{ORIGIN}/mitre">MITRE ATT&amp;CK coverage</a></li>
<li><a href="{ORIGIN}/actors">Threat actor gap analysis</a></li>
<li><a href="{ORIGIN}/observables">Observables: processes, event IDs, domains rules key on</a></li>
<li><a href="{ORIGIN}/digest">Weekly digest of new and updated rules</a></li>
</ul>"""
    return _page(SITE, desc, "/", "/api/og/site.png", body, og_type="website")
