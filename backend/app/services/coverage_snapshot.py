"""MITRE coverage snapshots + the newly-covered diff (issue #9).

Two halves:

- `write_coverage_snapshot(db)` — one aggregate pass over the corpus,
  upserted as today's (technique, source, rule_count) rows. Called by
  the worker after every successful full sync; rerun-safe (same-day
  rows are replaced).
- `compute_newly_covered(db, days, ...)` — the "just covered" signal.
  Prefers a snapshot diff (exact, point-in-time truth) when a snapshot
  at least `days` old exists; before that history has accumulated it
  falls back to git-derived `rule_created_date` minimums, flagged in
  the response so the UI can caption the provenance honestly.

Onboarding-flood guard: a source with NO rows at the baseline snapshot
was onboarded inside the window — every one of its techniques would
read "0 -> N". Those are reported under `new_sources`, not as
newly-covered techniques.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import date, timedelta
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.models.detection import Detection
from app.services.mitre import mitre_service
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)


async def _current_counts(db: AsyncSession) -> dict[tuple[str, str], int]:
    """(technique_id, source) -> rule count, from the live corpus.

    JSON-list aggregation is done in Python — portable across
    SQLite/Postgres and cheap at corpus scale (same pattern as the
    actor score bundle)."""
    rows = (
        await db.execute(select(Detection.source, Detection.mitre_techniques))
    ).all()
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for source, techniques in rows:
        for tid in techniques or []:
            if isinstance(tid, str) and tid:
                counts[(tid.upper(), source)] += 1
    return dict(counts)


async def write_coverage_snapshot(db: AsyncSession) -> int:
    """Write (replace) today's snapshot rows. Returns the row count."""
    counts = await _current_counts(db)
    today = utcnow().date()
    await db.execute(
        delete(MitreCoverageSnapshot).where(
            MitreCoverageSnapshot.snapshot_date == today
        )
    )
    db.add_all(
        MitreCoverageSnapshot(
            snapshot_date=today,
            technique_id=tid,
            source=source,
            rule_count=n,
        )
        for (tid, source), n in counts.items()
    )
    await db.commit()
    logger.info(
        f"Coverage snapshot {today}: {len(counts)} technique x source rows"
    )
    return len(counts)


async def _baseline_snapshot(
    db: AsyncSession, cutoff: date
) -> tuple[Optional[date], dict[tuple[str, str], int]]:
    """Newest snapshot taken ON OR BEFORE `cutoff`, as (date, counts)."""
    baseline_date = (
        await db.execute(
            select(MitreCoverageSnapshot.snapshot_date)
            .where(MitreCoverageSnapshot.snapshot_date <= cutoff)
            .order_by(MitreCoverageSnapshot.snapshot_date.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if baseline_date is None:
        return None, {}
    rows = (
        await db.execute(
            select(
                MitreCoverageSnapshot.technique_id,
                MitreCoverageSnapshot.source,
                MitreCoverageSnapshot.rule_count,
            ).where(MitreCoverageSnapshot.snapshot_date == baseline_date)
        )
    ).all()
    return baseline_date, {(t, s): n for t, s, n in rows}


def _technique_name(tid: str) -> str:
    info = mitre_service.get_technique(tid)
    return (info or {}).get("name", "")


async def compute_newly_covered(
    db: AsyncSession,
    days: int = 30,
    limit: int = 50,
    sources: Optional[list[str]] = None,
) -> dict:
    """The newly-covered payload — see module docstring for semantics."""
    await mitre_service.ensure_loaded()
    current = await _current_counts(db)
    cutoff = utcnow().date() - timedelta(days=days)
    baseline_date, baseline = await _baseline_snapshot(db, cutoff)

    if baseline_date is not None:
        method = "snapshot"
        baseline_sources = {s for (_t, s) in baseline}
        current_sources = {s for (_t, s) in current}
        new_sources = sorted(current_sources - baseline_sources)

        baseline_techs = {t for (t, _s), n in baseline.items() if n > 0}

        def had_at_baseline(tid: str, source: Optional[str] = None) -> bool:
            if source is not None:
                return baseline.get((tid, source), 0) > 0
            return tid in baseline_techs

        catalog_now: dict[str, dict[str, int]] = defaultdict(dict)
        for (tid, source), n in current.items():
            if n > 0:
                catalog_now[tid][source] = n

        catalog_new = []
        source_new = []
        for tid, per_source in catalog_now.items():
            if not had_at_baseline(tid):
                catalog_new.append((tid, per_source))
                continue
            for source, n in per_source.items():
                if source in new_sources:
                    continue  # onboarding flood, not incremental coverage
                if sources and source not in sources:
                    continue
                if not had_at_baseline(tid, source):
                    covered_elsewhere = sorted(
                        s for s in per_source if s != source
                    )
                    source_new.append((tid, source, n, covered_elsewhere))
    else:
        # Blind window — derive first-coverage from git-derived rule
        # creation dates. Upstream authorship, not our ingest, so a
        # freshly onboarded source with old rules does NOT flood.
        method = "rule_dates"
        new_sources = []
        rows = (
            await db.execute(
                select(
                    Detection.source,
                    Detection.mitre_techniques,
                    Detection.rule_created_date,
                )
            )
        ).all()
        first_seen: dict[tuple[str, str], date] = {}
        for source, techniques, created in rows:
            if created is None:
                continue
            d = created.date() if hasattr(created, "date") else created
            for tid in techniques or []:
                if not isinstance(tid, str) or not tid:
                    continue
                key = (tid.upper(), source)
                if key not in first_seen or d < first_seen[key]:
                    first_seen[key] = d

        catalog_first: dict[str, date] = {}
        for (tid, _source), d in first_seen.items():
            if tid not in catalog_first or d < catalog_first[tid]:
                catalog_first[tid] = d

        catalog_new = []
        source_new = []
        for tid, d in catalog_first.items():
            if d >= cutoff:
                per_source = {
                    s: current.get((tid, s), 0)
                    for (t, s) in current
                    if t == tid and current.get((tid, s), 0) > 0
                }
                catalog_new.append((tid, per_source))
        for (tid, source), d in first_seen.items():
            if d < cutoff or catalog_first.get(tid) == d:
                continue  # old news, or already counted catalog-wide
            if sources and source not in sources:
                continue
            n = current.get((tid, source), 0)
            if n <= 0:
                continue
            covered_elsewhere = sorted(
                s for (t, s) in current
                if t == tid and s != source and current.get((tid, s), 0) > 0
            )
            source_new.append((tid, source, n, covered_elsewhere))

    catalog_payload = [
        {
            "technique_id": tid,
            "technique_name": _technique_name(tid),
            "sources": dict(sorted(per_source.items())),
            "total_rules": sum(per_source.values()),
        }
        for tid, per_source in catalog_new
    ]
    catalog_payload.sort(key=lambda e: (-e["total_rules"], e["technique_id"]))

    source_payload = [
        {
            "technique_id": tid,
            "technique_name": _technique_name(tid),
            "source": source,
            "rule_count": n,
            "covered_elsewhere": covered_elsewhere,
        }
        for tid, source, n, covered_elsewhere in source_new
    ]
    source_payload.sort(
        key=lambda e: (-len(e["covered_elsewhere"]), e["technique_id"])
    )

    return {
        "method": method,
        "window_days": days,
        "baseline_date": baseline_date.isoformat() if baseline_date else None,
        "new_sources": new_sources,
        "catalog_newly_covered": catalog_payload[:limit],
        "source_newly_covered": source_payload[:limit],
    }
