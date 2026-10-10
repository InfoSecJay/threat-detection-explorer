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
from app.services import coverage_snapshot as _snapshots


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


async def comparable_baseline(
    db: AsyncSession, latest: date, days: int,
) -> tuple[Optional[date], bool]:
    """The snapshot to diff `latest` against: the newest one at least
    `days` old that is comparable (on or after STRICT_SNAPSHOT_SINCE,
    #172). While strict history is shorter than the window, the oldest
    comparable snapshot stands in and the second value is True so the
    payload can say the window was truncated; None when nothing
    comparable predates `latest`."""
    since = _snapshots.comparable_since()
    wanted = latest - timedelta(days=days)
    row = (
        await db.execute(
            select(func.max(MitreCoverageSnapshot.snapshot_date)).where(
                MitreCoverageSnapshot.snapshot_date <= wanted,
                MitreCoverageSnapshot.snapshot_date >= since,
            )
        )
    ).scalar()
    if row is not None:
        return row, False
    # No comparable snapshot is old enough. If nothing at all is that old
    # the history is simply short (insufficient_history, as before). If
    # an older, pre-switch snapshot exists the cut-off is what removed
    # it, so the oldest comparable one stands in, flagged.
    any_old_enough = (
        await db.execute(
            select(func.count()).select_from(MitreCoverageSnapshot).where(
                MitreCoverageSnapshot.snapshot_date <= wanted
            )
        )
    ).scalar()
    if not any_old_enough:
        return None, False
    oldest = (
        await db.execute(
            select(func.min(MitreCoverageSnapshot.snapshot_date)).where(
                MitreCoverageSnapshot.snapshot_date >= since,
                MitreCoverageSnapshot.snapshot_date < latest,
            )
        )
    ).scalar()
    return oldest, oldest is not None


async def compute_technique_deltas(
    db: AsyncSession, days: int = 7, limit: int = 10,
) -> dict:
    latest = await _latest_snapshot_date(db)
    if latest is None:
        return {
            "days": days, "method": "no_data", "current_date": None,
            "baseline_date": None, "gainers": [], "losers": [],
        }
    baseline, truncated = await comparable_baseline(db, latest, days)
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
    out = {
        "days": days,
        "method": "snapshot",
        "current_date": latest.isoformat(),
        "baseline_date": baseline.isoformat(),
        "gainers": gainers,
        "losers": losers,
    }
    if truncated:
        # Strict history (#172) is shorter than the window: the diff runs
        # from the oldest comparable snapshot instead.
        out["baseline_truncated"] = True
    return out
