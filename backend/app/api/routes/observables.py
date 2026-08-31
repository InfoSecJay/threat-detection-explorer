"""Observable pages API.

GET /api/observables                       the surfaces and their sizes
GET /api/observables/{type}                top values on one surface
GET /api/observables/{type}/{value}        profile of one value
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.corpus_cache import corpus_cache
from app.services.observables import OBSERVABLE_TYPES, observable_profile, top_values

router = APIRouter(prefix="/observables", tags=["observables"])


def _kind(kind: str) -> str:
    k = kind.lower()
    if k not in OBSERVABLE_TYPES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown observable type '{kind}'. One of: {', '.join(OBSERVABLE_TYPES)}",
        )
    return k


@router.get("")
async def list_types(db: AsyncSession = Depends(get_db)):
    """The surfaces with their distinct counts and top values -- eight
    scans, memoised on the corpus fingerprint."""
    return await corpus_cache.get(db, ("observable_types",), lambda: _compute_types(db), persist=True)


async def _compute_types(db: AsyncSession) -> dict:
    out = []
    for k, (_, filter_key, label) in OBSERVABLE_TYPES.items():
        top = await top_values(db, k, limit=5)
        out.append({"type": k, "label": label, "filter_key": filter_key, "distinct": top["distinct"], "top": top["values"]})
    return {"types": out}


@router.get("/{kind}")
async def list_values(
    kind: str,
    limit: int = Query(100, ge=10, le=500),
    source: Optional[str] = Query(None, description="Restrict to one source"),
    q: Optional[str] = Query(None, max_length=200, description="Case-insensitive substring of the value"),
    db: AsyncSession = Depends(get_db),
):
    k = _kind(kind)
    if q:
        # Searches are unbounded input; compute, do not memoise.
        return await top_values(db, k, limit=limit, source=source, q=q)
    return await corpus_cache.get(
        db, ("observable_top", k, limit, source), lambda: top_values(db, k, limit=limit, source=source),
    )


@router.get("/{kind}/{value:path}")
async def get_profile(kind: str, value: str, db: AsyncSession = Depends(get_db)):
    value = value.strip()
    if not value or len(value) > 512:
        raise HTTPException(status_code=400, detail="value must be 1-512 characters")
    profile = await observable_profile(db, _kind(kind), value)
    if profile["total_rules"] == 0:
        raise HTTPException(status_code=404, detail=f"No rules reference {kind} '{value}'")
    return profile
