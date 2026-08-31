"""Actors x sources coverage matrix (gap heatmap, issue #18 follow-up).

One scan of (source, mitre_techniques) builds technique -> source rule
counts; each actor's row is then a sum over its technique set, so the
whole matrix costs one query however many actors it shows.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.actor_scores import actor_score_service
from app.services.corpus_cache import corpus_cache
from app.services.mitre import mitre_service
from app.services.repository_sync import ALL_REPOSITORY_NAMES

Kind = Literal["groups", "software"]


async def technique_source_counts(db: AsyncSession) -> dict[str, dict[str, int]]:
    """{technique_id: {source: rule_count}} over the whole corpus,
    memoised on the corpus fingerprint (shared by the heatmap and the
    per-source breakdown on every actor page)."""
    return await corpus_cache.get(db, ("technique_source_counts",), lambda: _scan_technique_sources(db), persist=True)


async def _scan_technique_sources(db: AsyncSession) -> dict[str, dict[str, int]]:
    rows = (await db.execute(select(Detection.source, Detection.mitre_techniques))).all()
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for source, techniques in rows:
        for tid in techniques or []:
            if isinstance(tid, str) and tid:
                out[tid.upper()][source] += 1
    return out


async def coverage_matrix(
    db: AsyncSession, kind: Kind = "groups", limit: int = 40, sort: str = "weighted_gap",
    min_techniques: int = 5,
) -> dict:
    await mitre_service.ensure_loaded()
    bundle = await actor_score_service.get(db)
    catalog = mitre_service.get_all_groups() if kind == "groups" else mitre_service.get_all_software()
    scores = bundle.groups if kind == "groups" else bundle.software
    ts_counts = await technique_source_counts(db)

    entities = []
    for eid, entity in catalog.items():
        if entity.get("deprecated"):
            continue
        sc = scores.get(eid)
        techs = [t.upper() for t in entity.get("techniques", []) if isinstance(t, str)]
        if not sc or len(techs) < min_techniques:
            continue
        entities.append((eid, entity, sc, techs))

    key = {
        "weighted_gap": lambda e: (-e[2].weighted_gap, e[1].get("name", "")),
        "gap_count": lambda e: (-e[2].gap_count, e[1].get("name", "")),
        "technique_count": lambda e: (-len(e[3]), e[1].get("name", "")),
        "name": lambda e: e[1].get("name", "").lower(),
    }.get(sort, lambda e: (-e[2].weighted_gap, e[1].get("name", "")))
    entities.sort(key=key)

    sources = list(ALL_REPOSITORY_NAMES)
    rows = []
    for eid, entity, sc, techs in entities[:limit]:
        by_source = {s: {"techniques_covered": 0, "rule_count": 0} for s in sources}
        covered_any = 0
        for tid in techs:
            per = ts_counts.get(tid)
            if not per:
                continue
            covered_any += 1
            for s, n in per.items():
                if s in by_source:
                    by_source[s]["techniques_covered"] += 1
                    by_source[s]["rule_count"] += n
        rows.append({
            "id": eid,
            "name": entity.get("name", eid),
            "kind": kind,
            "technique_count": len(techs),
            "covered_technique_count": covered_any,
            "gap_count": sc.gap_count,
            "weighted_gap": round(sc.weighted_gap, 4),
            "weighted_coverage": round(sc.weighted_coverage, 4) if sc.weighted_coverage is not None else None,
            "by_source": {s: v for s, v in by_source.items() if v["techniques_covered"]},
        })

    # Column totals: how many of the shown actors each source covers at all.
    source_totals = {
        s: sum(1 for r in rows if s in r["by_source"]) for s in sources
    }
    return {
        "kind": kind,
        "sort": sort,
        "limit": limit,
        "total_entities": len(entities),
        "sources": sources,
        "source_totals": source_totals,
        "rows": rows,
    }
