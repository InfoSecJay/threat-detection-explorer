"""MITRE ATT&CK API routes."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.corpus_cache import corpus_cache
from app.services.mitre import mitre_service
from app.services.technique_profile import technique_profile

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("")
async def get_mitre_data():
    """Get all MITRE ATT&CK tactics and techniques."""
    await mitre_service.ensure_loaded()

    return {
        "tactics": mitre_service.get_all_tactics(),
        "techniques": mitre_service.get_all_techniques(),
        "stats": mitre_service.get_stats(),
    }


@router.get("/tactics")
async def get_tactics():
    """Get all MITRE ATT&CK tactics."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_all_tactics()


@router.get("/tactics/{tactic_id}")
async def get_tactic(tactic_id: str):
    """Get a specific MITRE ATT&CK tactic by ID."""
    await mitre_service.ensure_loaded()
    tactic = mitre_service.get_tactic(tactic_id.upper())
    if not tactic:
        raise HTTPException(status_code=404, detail=f"Tactic {tactic_id} not found")
    return tactic


@router.get("/techniques")
async def get_techniques():
    """Get all MITRE ATT&CK techniques."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_all_techniques()


@router.get("/techniques/{technique_id}")
async def get_technique(technique_id: str):
    """Get a specific MITRE ATT&CK technique by ID."""
    await mitre_service.ensure_loaded()
    technique = mitre_service.get_technique(technique_id.upper())
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return technique


@router.post("/refresh")
async def refresh_mitre_data():
    """Force refresh MITRE ATT&CK data from the official repository."""
    success = await mitre_service.refresh()
    return {
        "success": success,
        "stats": mitre_service.get_stats(),
    }


@router.get("/stats")
async def get_mitre_stats():
    """Get statistics about loaded MITRE ATT&CK data."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_stats()


@router.get("/coverage-by-data-source")
async def coverage_by_data_source(
    limit: int = Query(40, ge=5, le=200, description="Techniques (rows), most rules first"),
    sources: int = Query(15, ge=3, le=60, description="Data sources (columns), most rules first"),
    db: AsyncSession = Depends(get_db),
):
    """Techniques x canonical data sources: how many rules detect each
    technique from each log source. Answers "what can I detect with the
    telemetry I have". One scan, memoised on the corpus fingerprint."""
    await mitre_service.ensure_loaded()
    key = ("mitre_ds_matrix", limit, sources, mitre_service.get_stats()["last_fetch"])
    return await corpus_cache.get(db, key, lambda: _compute_ds_matrix(db, limit, sources))


async def _compute_ds_matrix(db: AsyncSession, limit: int, n_sources: int) -> dict:
    from collections import Counter, defaultdict

    from sqlalchemy import select

    from app.models.detection import Detection

    rows = (await db.execute(select(Detection.data_sources, Detection.mitre_techniques))).all()
    per_tech: dict[str, Counter] = defaultdict(Counter)
    tech_total: Counter = Counter()
    ds_total: Counter = Counter()
    for data_sources, techniques in rows:
        tids = {t.upper() for t in (techniques or []) if isinstance(t, str) and t}
        dss = [d for d in (data_sources or []) if isinstance(d, str) and d and d != "unknown"]
        for tid in tids:
            tech_total[tid] += 1
            for ds in dss:
                per_tech[tid][ds] += 1
                ds_total[ds] += 1
    columns = [ds for ds, _ in ds_total.most_common(n_sources)]
    out_rows = []
    for tid, total in tech_total.most_common(limit):
        info = mitre_service.get_technique(tid) or {}
        tactic_ids = info.get("tactics") or []
        tactic = mitre_service.get_tactic(tactic_ids[0]) if tactic_ids else None
        out_rows.append({
            "technique_id": tid,
            "technique_name": info.get("name", ""),
            "tactic": (tactic or {}).get("name", ""),
            "rules": total,
            "by_data_source": {ds: per_tech[tid][ds] for ds in columns if per_tech[tid][ds]},
        })
    return {
        "data_sources": [{"id": ds, "rules": ds_total[ds]} for ds in columns],
        "rows": out_rows,
        "total_techniques": len(tech_total),
    }


@router.get("/techniques/{technique_id}/profile")
async def get_technique_profile(technique_id: str, db: AsyncSession = Depends(get_db)):
    """Beyond the rule list: per-source coverage + hygiene, how each
    vendor detects the technique (top observables per source), the
    groups and software that use it, and week-over-week momentum."""
    profile = await technique_profile(db, technique_id)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return profile
