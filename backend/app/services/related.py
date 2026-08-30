"""Related rules: the same behaviour written by other vendors.

For one rule, find rules that share what it keys on -- the same
technique plus the same process names / event IDs / registry keys /
API actions / paths / indicators -- and rank them by how much they
share. Other sources rank first at equal score: the point of the site
is cross-vendor comparison, and a rule's siblings in its own repo are
one click away already.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache

# (column, label, weight) -- a shared process name says more than a
# shared technique tag; a shared event ID less than either.
_SURFACES = (
    ("extracted_process_names", "process", 3.0),
    ("extracted_registry_keys", "registry key", 3.0),
    ("extracted_api_actions", "API action", 3.0),
    ("extracted_file_paths", "path", 2.0),
    ("extracted_network_indicators", "indicator", 2.0),
    ("extracted_event_ids", "event ID", 1.0),
    ("extracted_source_tables", "source table", 0.5),
)
_MAX_TERMS = 8
_CANDIDATES = 400
_RESULTS = 12

_COLS = (
    Detection.id, Detection.title, Detection.source, Detection.severity, Detection.language,
    Detection.mitre_techniques, Detection.data_sources, Detection.quality_score,
    Detection.extracted_process_names, Detection.extracted_registry_keys, Detection.extracted_api_actions,
    Detection.extracted_file_paths, Detection.extracted_network_indicators, Detection.extracted_event_ids,
    Detection.extracted_source_tables,
)


def _lower_set(values) -> set[str]:
    return {str(v).lower() for v in (values or []) if isinstance(v, str) and v.strip()}


async def related_rules(db: AsyncSession, detection: Detection, limit: int = _RESULTS) -> dict:
    return await corpus_cache.get(
        db, ("related", detection.id, limit), lambda: _compute(db, detection, limit),
    )


async def _compute(db: AsyncSession, d: Detection, limit: int) -> dict:
    techniques = [t.upper() for t in (d.mitre_techniques or []) if isinstance(t, str) and t][:5]
    mine = {col: _lower_set(getattr(d, col)) for col, _l, _w in _SURFACES}
    conds = [cast(Detection.mitre_techniques, String).ilike(f'%"{t}"%') for t in techniques]
    for col, _label, _w in _SURFACES:
        for v in sorted(mine[col])[:_MAX_TERMS]:
            escaped = v.replace("%", "\\%").replace("_", "\\_")
            conds.append(cast(getattr(Detection, col), String).ilike(f'%"{escaped}"%', escape="\\"))
    if not conds:
        return {"id": d.id, "related": []}

    rows = (
        await db.execute(select(*_COLS).where(or_(*conds)).where(Detection.id != d.id).limit(_CANDIDATES))
    ).all()
    my_techs = set(techniques)
    my_ds = _lower_set(d.data_sources)
    scored = []
    for r in rows:
        (rid, title, source, severity, language, r_techs, r_ds, quality, *surfaces) = r
        score = 0.0
        reasons: list[str] = []
        shared_t = sorted(my_techs & {t.upper() for t in (r_techs or []) if isinstance(t, str)})
        if shared_t:
            score += 2.0 * len(shared_t)
            reasons.append(f"technique {', '.join(shared_t[:3])}")
        for (col, label, weight), values in zip(_SURFACES, surfaces):
            shared = sorted(mine[col] & _lower_set(values))
            if shared:
                score += weight * min(len(shared), 4)
                reasons.append(f"{label} {', '.join(shared[:3])}")
        if my_ds and (my_ds & _lower_set(r_ds)):
            score += 0.5
        if score <= 0:
            continue
        scored.append({
            "id": rid, "title": title, "source": source, "severity": severity, "language": language,
            "quality_score": quality, "score": round(score, 1), "reasons": reasons,
            "other_vendor": source != d.source,
        })
    scored.sort(key=lambda x: (-x["score"], not x["other_vendor"], x["title"].lower()))
    return {"id": d.id, "related": scored[:limit]}


async def related_for_id(db: AsyncSession, detection_id: str, limit: int = _RESULTS) -> Optional[dict]:
    d = await db.get(Detection, detection_id)
    if d is None:
        return None
    return await related_rules(db, d, limit)
