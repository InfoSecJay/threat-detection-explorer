"""Open Graph card images (#76 / teardown F01).

1200x630 PNG cards in the site's terminal palette, rendered with
Pillow at request time and cached in-process. A rule link pasted into
Slack/LinkedIn/Discord unfurls into a readable card instead of a bare
URL -- the teardown called this the single highest-leverage change.

Pillow >= 10.1 ships a scalable embedded font via
ImageFont.load_default(size=...), so no font files are bundled; if
that ever fails we degrade to the tiny bitmap font rather than 500.
"""

from __future__ import annotations

import io
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.mitre import mitre_service

router = APIRouter(prefix="/og", tags=["og"])

W, H = 1200, 630
BG = (1, 4, 9)          # void
FG = (230, 237, 243)    # near-white
GREEN = (0, 255, 136)   # matrix accent
GRAY = (110, 118, 129)
SEVERITY_COLOR = {
    "critical": (248, 81, 73),
    "high": (255, 123, 114),
    "medium": (210, 153, 34),
    "low": (63, 185, 80),
}

_HEADERS = {"Cache-Control": "public, s-maxage=86400, stale-while-revalidate=604800"}


@lru_cache(maxsize=8)
def _font(size: int):
    from PIL import ImageFont

    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # Pillow < 10.1
        return ImageFont.load_default()


def _wrap(draw, text: str, font, max_width: int, max_lines: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for w in words:
        cand = f"{current} {w}".strip()
        if draw.textlength(cand, font=font) <= max_width:
            current = cand
        else:
            lines.append(current)
            current = w
            if len(lines) == max_lines:
                break
    if current and len(lines) < max_lines:
        lines.append(current)
    if len(lines) == max_lines and words and " ".join(lines).count(" ") + 1 < len(words):
        lines[-1] = lines[-1][:60].rstrip() + "…"
    return lines or [text[:60]]


def _card(title: str, badges: list[tuple[str, tuple[int, int, int]]], footer_left: str) -> bytes:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Frame + accent bar
    d.rectangle([0, 0, W - 1, H - 1], outline=(35, 42, 52), width=2)
    d.rectangle([0, 0, 10, H], fill=GREEN)

    # Wordmark
    d.text((60, 48), "DETECTION", font=_font(34), fill=GREEN)
    d.text((266, 48), "EXPLORER", font=_font(34), fill=FG)
    d.text((60, 92), "open detection rules, one schema", font=_font(20), fill=GRAY)

    # Title (wrapped, up to 3 lines)
    tf = _font(56)
    y = 190
    for line in _wrap(d, title, tf, W - 140, 3):
        d.text((60, y), line, font=tf, fill=FG)
        y += 72

    # Badges
    bf = _font(26)
    x = 60
    by = min(max(y + 26, 420), 470)
    for text, color in badges[:5]:
        tw = d.textlength(text, font=bf)
        d.rounded_rectangle([x, by, x + tw + 28, by + 44], radius=6, outline=color, width=2)
        d.text((x + 14, by + 8), text, font=bf, fill=color)
        x += tw + 48

    # Footer
    d.line([60, H - 74, W - 60, H - 74], fill=(35, 42, 52), width=2)
    d.text((60, H - 58), footer_left, font=_font(22), fill=GRAY)
    site = "detectionexplorer.io"
    d.text((W - 60 - d.textlength(site, font=_font(22)), H - 58), site, font=_font(22), fill=GREEN)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _png(data: bytes) -> Response:
    return Response(content=data, media_type="image/png", headers=_HEADERS)


@router.get("/detection/{detection_id}.png")
async def og_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    det = await db.get(Detection, detection_id)
    if det is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    badges: list[tuple[str, tuple[int, int, int]]] = [(det.source.upper(), GREEN)]
    if det.language:
        badges.append((det.language.upper(), FG))
    if det.severity and det.severity != "unknown":
        badges.append((det.severity.upper(), SEVERITY_COLOR.get(det.severity, GRAY)))
    techniques = [t for t in (det.mitre_techniques or []) if isinstance(t, str)][:2]
    for t in techniques:
        badges.append((t, GRAY))
    return _png(_card(det.title, badges, "detection rule"))


@router.get("/technique/{technique_id}.png")
async def og_technique(technique_id: str):
    await mitre_service.ensure_loaded()
    tid = technique_id.upper()
    info = mitre_service.get_technique(tid)
    if not info:
        raise HTTPException(status_code=404, detail="Technique not found")
    return _png(_card(
        f"{tid} {info.get('name', '')}",
        [("MITRE ATT&CK", GREEN), ("CROSS-VENDOR COVERAGE", FG)],
        "technique coverage",
    ))


@router.get("/actor/{actor_id}.png")
async def og_actor(actor_id: str):
    await mitre_service.ensure_loaded()
    aid = actor_id.upper()
    info = mitre_service.get_all_groups().get(aid) or mitre_service.get_all_software().get(aid)
    if not info:
        raise HTTPException(status_code=404, detail="Actor not found")
    return _png(_card(
        f"{info.get('name', aid)} ({aid})",
        [("THREAT ACTOR" if aid.startswith("G") else "SOFTWARE", GREEN), ("DETECTION GAP ANALYSIS", FG)],
        "adversary coverage",
    ))


@router.get("/site.png")
async def og_site():
    return _png(_card(
        "Open-source detection rules, one schema",
        [("13 SOURCES", GREEN), ("MITRE ATT&CK", FG), ("OBSERVABLES", GRAY)],
        "detectionexplorer.io",
    ))
