"""Technique profile: what the corpus knows about one ATT&CK technique
beyond the rule list -- per-source coverage and hygiene, how each
vendor detects it (the observables their rules key on), which actors
and software use it, and week-over-week momentum from the coverage
snapshots.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Optional

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.models.detection import Detection
from app.services.mitre import mitre_service

_SURFACES = {
    "process": Detection.extracted_process_names,
    "eventid": Detection.extracted_event_ids,
    "action": Detection.extracted_api_actions,
    "table": Detection.extracted_source_tables,
    "path": Detection.extracted_file_paths,
    "registry": Detection.extracted_registry_keys,
    "network": Detection.extracted_network_indicators,
}


async def _momentum(db: AsyncSession, technique_id: str, days: int = 7) -> dict:
    latest = (await db.execute(select(func.max(MitreCoverageSnapshot.snapshot_date)))).scalar()
    if latest is None:
        return {"method": "no_data", "current": None, "baseline": None, "delta": None}
    baseline_day = (
        await db.execute(
            select(func.max(MitreCoverageSnapshot.snapshot_date)).where(
                MitreCoverageSnapshot.snapshot_date <= latest - timedelta(days=days)
            )
        )
    ).scalar()

    async def total_on(day) -> int:
        return (
            await db.execute(
                select(func.coalesce(func.sum(MitreCoverageSnapshot.rule_count), 0)).where(
                    MitreCoverageSnapshot.snapshot_date == day,
                    MitreCoverageSnapshot.technique_id == technique_id,
                )
            )
        ).scalar() or 0

    current = await total_on(latest)
    if baseline_day is None:
        return {"method": "insufficient_history", "current": current, "baseline": None, "delta": None}
    baseline = await total_on(baseline_day)
    return {"method": "snapshot", "current": current, "baseline": baseline, "delta": current - baseline,
            "baseline_date": baseline_day.isoformat()}


async def technique_profile(db: AsyncSession, technique_id: str, per_surface: int = 6) -> Optional[dict]:
    await mitre_service.ensure_loaded()
    tid = technique_id.upper()
    tech = mitre_service.get_technique(tid)
    if tech is None:
        return None

    rows = (
        await db.execute(
            select(
                Detection.source, Detection.severity, Detection.quality_score,
                *[col for col in _SURFACES.values()],
            ).where(cast(Detection.mitre_techniques, String).ilike(f'%"{tid}"%'))
        )
    ).all()

    by_source: dict[str, dict] = {}
    obs_by_source: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    severities: Counter[str] = Counter()
    for row in rows:
        source, severity, quality = row[0], row[1], row[2]
        entry = by_source.setdefault(source, {"rules": 0, "scored": 0, "hygiene_sum": 0})
        entry["rules"] += 1
        if quality is not None:
            entry["scored"] += 1
            entry["hygiene_sum"] += quality
        severities[severity or "unknown"] += 1
        for name, values in zip(_SURFACES.keys(), row[3:]):
            for v in values or []:
                if isinstance(v, str) and v:
                    obs_by_source[source][name][v] += 1

    sources_out = {
        src: {
            "rules": e["rules"],
            "hygiene_avg": round(e["hygiene_sum"] / e["scored"], 1) if e["scored"] else None,
            "observables": {
                surface: [{"value": v, "rules": n} for v, n in counter.most_common(per_surface)]
                for surface, counter in obs_by_source[src].items() if counter
            },
        }
        for src, e in sorted(by_source.items(), key=lambda kv: (-kv[1]["rules"], kv[0]))
    }

    groups = [
        {"id": gid, "name": g.get("name", gid), "technique_count": len(g.get("techniques", []))}
        for gid, g in mitre_service.get_all_groups().items()
        if tid in {t.upper() for t in g.get("techniques", [])} and not g.get("deprecated")
    ]
    software = [
        {"id": sid, "name": s.get("name", sid), "type": s.get("type", "unknown")}
        for sid, s in mitre_service.get_all_software().items()
        if tid in {t.upper() for t in s.get("techniques", [])} and not s.get("deprecated")
    ]
    groups.sort(key=lambda g: g["name"].lower())
    software.sort(key=lambda s: s["name"].lower())

    return {
        "technique_id": tid,
        "name": tech.get("name", ""),
        "total_rules": len(rows),
        "by_severity": dict(severities.most_common()),
        "sources": sources_out,
        "groups": groups,
        "software": software,
        "momentum": await _momentum(db, tid),
    }
