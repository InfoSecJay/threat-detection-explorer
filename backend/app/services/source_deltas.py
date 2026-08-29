"""Per-source net rule-count deltas over a window (issue #19).

Every completed whole-corpus sync job stores, per repository,
``rules_stored`` -- which is the source's full corpus size after that
night's ingest (every discovered file is upserted, so stored == corpus;
verified against ``repositories.rule_count`` 2026-08-29). That makes
``sync_jobs.repository_results`` a free daily history of per-source
rule counts, and a week-over-week delta is just "latest minus the
newest job at least ``days`` old".

Why not the coverage snapshot table: it counts (technique, source)
pairs, so a rule tagged with three techniques weighs three -- fine for
coverage diffs, wrong for "how many rules did Sigma add this week".
Why not git: rule_created_date only sees additions; removals and
renames are invisible. The job history sees the net.

``method`` tells the caller what it got:
  - ``sync_jobs``            both endpoints found; deltas are exact
  - ``insufficient_history`` no job at least ``days`` old yet; only
                             ``current`` is populated, deltas are None
  - ``no_data``              no completed whole-corpus job at all
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sync_job import SyncJob
from app.utils.datetime_utils import to_utc_iso


def _stored_counts(job: Optional[SyncJob]) -> dict[str, int]:
    """{source: rules_stored} for repos whose ingest succeeded."""
    if job is None or not isinstance(job.repository_results, dict):
        return {}
    out: dict[str, int] = {}
    for name, result in job.repository_results.items():
        if not isinstance(result, dict) or not result.get("ingest_success"):
            continue
        stored = result.get("rules_stored")
        if isinstance(stored, int) and stored >= 0:
            out[name] = stored
    return out


async def _latest_full_job(
    db: AsyncSession, *, completed_before=None,
) -> Optional[SyncJob]:
    query = (
        select(SyncJob)
        .where(SyncJob.status == "completed")
        .where(SyncJob.repository.is_(None))
        .where(SyncJob.repository_results.is_not(None))
        .order_by(desc(SyncJob.completed_at))
        .limit(1)
    )
    if completed_before is not None:
        query = query.where(SyncJob.completed_at <= completed_before)
    return (await db.execute(query)).scalar_one_or_none()


async def compute_source_deltas(db: AsyncSession, days: int = 7) -> dict:
    latest = await _latest_full_job(db)
    if latest is None or latest.completed_at is None:
        return {
            "days": days,
            "method": "no_data",
            "current_job_id": None,
            "current_at": None,
            "baseline_job_id": None,
            "baseline_at": None,
            "by_source": {},
        }

    baseline = await _latest_full_job(
        db, completed_before=latest.completed_at - timedelta(days=days),
    )
    current = _stored_counts(latest)
    previous = _stored_counts(baseline)

    by_source: dict[str, dict] = {}
    for name in sorted(set(current) | set(previous)):
        cur = current.get(name)
        prev = previous.get(name) if baseline is not None else None
        entry: dict = {"current": cur, "baseline": prev, "delta": None}
        if cur is not None and prev is not None:
            entry["delta"] = cur - prev
        by_source[name] = entry

    return {
        "days": days,
        "method": "sync_jobs" if baseline is not None else "insufficient_history",
        "current_job_id": latest.id,
        "current_at": to_utc_iso(latest.completed_at),
        "baseline_job_id": baseline.id if baseline else None,
        "baseline_at": to_utc_iso(baseline.completed_at) if baseline else None,
        "by_source": by_source,
    }
