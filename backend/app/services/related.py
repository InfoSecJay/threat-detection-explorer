"""Related rules: the same behaviour written by other vendors.

For one rule, find rules that share what it keys on and rank them by
how much they share. Other sources rank first at equal score: the
point of the site is cross-vendor comparison, and a rule's siblings in
its own repo are one click away already.

"Same behaviour" (DX-02) requires at least one shared OBSERVABLE --
process name / event ID / registry key / API action / path /
indicator. A shared ATT&CK technique alone is not behaviour: two rules
both tagged T1055 can work in unrelated ways. Technique-only matches
are still returned, in their own `technique_only` bucket, so the UI
can show them as "shares a technique" rather than "same behaviour."
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
        return {"id": d.id, "related": [], "same_source": [], "technique_only": []}

    rows = (
        await db.execute(select(*_COLS).where(or_(*conds)).where(Detection.id != d.id).limit(_CANDIDATES))
    ).all()
    my_techs = set(techniques)
    my_ds = _lower_set(d.data_sources)
    scored = []
    technique_only = []
    for r in rows:
        (rid, title, source, severity, language, r_techs, r_ds, quality, *surfaces) = r
        score = 0.0
        observable_reasons: list[str] = []
        has_observable = False  # DX-02: "same behaviour" requires a real shared
        # observable (process/registry/API/path/indicator/event ID), not just
        # an ATT&CK tag both rules happen to carry. `extracted_*` already
        # excludes negated/excluded values (field_extractor.py), so any hit
        # here is something both rules positively key on.
        shared_t = sorted(my_techs & {t.upper() for t in (r_techs or []) if isinstance(t, str)})
        technique_reason = f"technique {', '.join(shared_t[:3])}" if shared_t else None
        if shared_t:
            # Supplementary context, not a qualifying signal on its own --
            # weighted below any single observable surface.
            score += 1.0 * len(shared_t)
        for (col, label, weight), values in zip(_SURFACES, surfaces):
            shared = sorted(mine[col] & _lower_set(values))
            if not shared:
                continue
            score += weight * min(len(shared), 4)
            if col == "extracted_source_tables":
                # "Also an inbound email rule" alone is not the same
                # behaviour (teardown F12) -- boosts score, never qualifies.
                continue
            observable_reasons.append(f"{label} {', '.join(shared[:3])}")
            has_observable = True
        if my_ds and (my_ds & _lower_set(r_ds)):
            score += 0.5
        if score <= 0:
            continue
        entry = {
            "id": rid, "title": title, "source": source, "severity": severity, "language": language,
            "quality_score": quality, "score": round(score, 1),
            "other_vendor": source != d.source,
        }
        if has_observable:
            entry["reasons"] = observable_reasons + ([technique_reason] if technique_reason else [])
            scored.append(entry)
        elif technique_reason:
            # Shares an ATT&CK technique only -- no shared observable means
            # this is not verified as the same behaviour (DX-02). Collapsed
            # into its own group instead of padding "same behaviour".
            entry["reasons"] = [technique_reason]
            technique_only.append(entry)
    scored.sort(key=lambda x: (-x["score"], x["title"].lower()))
    technique_only.sort(key=lambda x: (-x["score"], x["title"].lower()))
    cross = [x for x in scored if x["other_vendor"]]
    same = [x for x in scored if not x["other_vendor"]]
    return {
        "id": d.id, "related": cross[:limit], "same_source": same[:6],
        "technique_only": technique_only[:limit],
    }


async def related_for_id(db: AsyncSession, detection_id: str, limit: int = _RESULTS) -> Optional[dict]:
    from app.services.detection_resolver import resolve_detection

    d, _via_alias = await resolve_detection(db, detection_id)
    if d is None:
        return None
    return await related_rules(db, d, limit)
