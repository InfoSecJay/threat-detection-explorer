"""Technique-level week-over-week rule deltas from the coverage snapshot
table (issue #19, second half).

`mitre_coverage_snapshot` stores (snapshot_date, technique, source,
rule_count) once per nightly sync. "Momentum" for a technique is the
catalog-wide rule count on the latest snapshot minus the newest
snapshot at least `days` old. Counts are technique x source pairs, so a
rule tagged with three techniques contributes to three rows -- right
for "where is coverage growing", not for "how many rules were added"
(that is /trending/source-deltas).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.coverage_snapshot import MitreCoverageSnapshot


async def _latest_snapshot_date(
    db: AsyncSession, *, on_or_before: Optional[date] = None,
) -> Optional[date]:
    query = select(func.max(MitreCoverageSnapshot.snapshot_date))
    if on_or_before is not None:
        query = query.where(MitreCoverageSnapshot.snapshot_date <= on_or_before)
    return (await db.execute(query)).scalar()


async def _counts_on(db: AsyncSession, day: date) -> tuple[dict[str, int], dict[str, set[str]]]:
    """technique -> total rule_count, technique -> sources with rules, for one day."""
    rows = (
        await db.execute(
            select(
                MitreCoverageSnapshot.technique_id,
                MitreCoverageSnapshot.source,
                MitreCoverageSnapshot.rule_count,
            ).where(MitreCoverageSnapshot.snapshot_date == day)
        )
    ).all()
    totals: dict[str, int] = defaultdict(int)
    sources: dict[str, set[str]] = defaultdict(set)
    for tid, source, count in rows:
        if count:
            totals[tid] += count
            sources[tid].add(source)
    return dict(totals), dict(sources)


async def compute_technique_deltas(
    db: AsyncSession, days: int = 7, limit: int = 10,
) -> dict:
    latest = await _latest_snapshot_date(db)
    if latest is None:
        return {
            "days": days, "method": "no_data", "current_date": None,
            "baseline_date": None, "gainers": [], "losers": [],
        }
    baseline = await _latest_snapshot_date(db, on_or_before=latest - timedelta(days=days))
    if baseline is None:
        return {
            "days": days, "method": "insufficient_history",
            "current_date": latest.isoformat(), "baseline_date": None,
            "gainers": [], "losers": [],
        }

    current, current_sources = await _counts_on(db, latest)
    previous, previous_sources = await _counts_on(db, baseline)

    entries = []
    for tid in set(current) | set(previous):
        cur = current.get(tid, 0)
        prev = previous.get(tid, 0)
        if cur == prev:
            continue
        entries.append({
            "technique_id": tid,
            "current": cur,
            "baseline": prev,
            "delta": cur - prev,
            # Sources that newly cover / dropped the technique in the window.
            "sources_added": sorted(current_sources.get(tid, set()) - previous_sources.get(tid, set())),
            "sources_removed": sorted(previous_sources.get(tid, set()) - current_sources.get(tid, set())),
        })

    gainers = sorted((e for e in entries if e["delta"] > 0), key=lambda e: (-e["delta"], e["technique_id"]))[:limit]
    losers = sorted((e for e in entries if e["delta"] < 0), key=lambda e: (e["delta"], e["technique_id"]))[:limit]
    return {
        "days": days,
        "method": "snapshot",
        "current_date": latest.isoformat(),
        "baseline_date": baseline.isoformat(),
        "gainers": gainers,
        "losers": losers,
    }
