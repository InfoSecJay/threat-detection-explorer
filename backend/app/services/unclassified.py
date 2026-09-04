"""Unclassified burn-down (teardown R14 / #112).

The methodology page promises that rules the resolver cannot place
show `unknown` rather than a guess. This makes the cost of that
promise visible: how many rules per source carry `unknown` in each
normalized field, today and over time, so mapping work is a public
backlog instead of an aside.

Three parts:
- `current_counts(db)` -- one pass over the live corpus, grouped by
  (source, field). Cached per corpus fingerprint by the route.
- `write_unclassified_snapshot(db)` -- today's counts as rows, called
  by the worker after every successful sync (same-day rerun replaces).
  Also backfills any earlier day that has a corpus snapshot but no
  rows here, so history starts at the first corpus snapshot rather
  than at this feature's deploy.
- `history(db, days)` -- the per-field daily totals the page charts.

Which fields count as "unclassified": a scalar equal to `unknown`, or
a taxonomy list containing `unknown`. `not_applicable` (status) and
`none` (language) are deliberate values, not failures, and never count.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import date, timedelta
from typing import Iterable

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corpus_snapshot import CorpusSnapshot
from app.models.detection import Detection
from app.models.unclassified_snapshot import UnclassifiedSnapshot
from app.services.corpus_snapshot import read_corpus_snapshot
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

# Field -> (Detection column name, is_list). Order is display order.
UNCLASSIFIED_FIELDS: dict[str, tuple[str, bool]] = {
    "platforms": ("platforms", True),
    # Attack-surface domain (#103 / #136). `products` is left out on
    # purpose: an empty products list is a fact, not a gap.
    "domains": ("domains", True),
    "data_sources": ("data_sources", True),
    "event_types": ("event_types", True),
    "status": ("status", False),
    "severity": ("severity", False),
    "language": ("language", False),
    "mitre_techniques": ("mitre_techniques", True),  # empty list = no mapping
}

# Catalog filter key each field maps to, so the page can link straight
# to the offending rules (`/detections?sources=x&platforms=unknown`).
CATALOG_FILTER_KEY: dict[str, str] = {
    "platforms": "platforms",
    "domains": "domains",
    "data_sources": "data_sources_normalized",
    "event_types": "event_categories",
    "status": "statuses",
    "severity": "severities",
    "language": "languages",
}


def _is_unclassified(field: str, value) -> bool:
    if field == "mitre_techniques":
        return not value
    if isinstance(value, list):
        return "unknown" in value
    return value == "unknown"


async def current_counts(db: AsyncSession) -> dict:
    """{source: {field: count, "_total": n}} from the live corpus."""
    cols = [Detection.source] + [getattr(Detection, c) for c, _ in UNCLASSIFIED_FIELDS.values()]
    rows = (await db.execute(select(*cols))).all()
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        source = row[0]
        out[source]["_total"] += 1
        for i, field in enumerate(UNCLASSIFIED_FIELDS, start=1):
            if _is_unclassified(field, row[i]):
                out[source][field] += 1
    return {s: dict(v) for s, v in out.items()}


def _counts_from_rows(rule_dicts: Iterable[dict]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for r in rule_dicts:
        out["_total"] += 1
        for field, (col, _is_list) in UNCLASSIFIED_FIELDS.items():
            if _is_unclassified(field, r.get(col)):
                out[field] += 1
    return dict(out)


async def _write_day(db: AsyncSession, day: date, counts: dict[str, dict[str, int]]) -> int:
    await db.execute(delete(UnclassifiedSnapshot).where(UnclassifiedSnapshot.snapshot_date == day))
    n = 0
    for source, fields in counts.items():
        total = fields.get("_total", 0)
        for field in UNCLASSIFIED_FIELDS:
            db.add(UnclassifiedSnapshot(
                snapshot_date=day, source=source, field=field,
                rule_count=fields.get(field, 0), total_rules=total,
            ))
            n += 1
    return n


async def write_unclassified_snapshot(db: AsyncSession, snapshot_date: date | None = None) -> dict[str, int]:
    """Write today's rows; backfill days that have a corpus snapshot but
    no unclassified rows. Returns {day_iso: rows_written}."""
    day = snapshot_date or utcnow().date()
    written: dict[str, int] = {}

    have = set((await db.execute(select(UnclassifiedSnapshot.snapshot_date).distinct())).scalars().all())
    corpus_days = set((await db.execute(select(CorpusSnapshot.snapshot_date).distinct())).scalars().all())
    for past in sorted(corpus_days - have - {day}):
        sources = (
            await db.execute(
                select(CorpusSnapshot.source).where(CorpusSnapshot.snapshot_date == past)
            )
        ).scalars().all()
        counts = {s: _counts_from_rows(await read_corpus_snapshot(db, past, s)) for s in sources}
        written[past.isoformat()] = await _write_day(db, past, counts)
        await db.flush()

    written[day.isoformat()] = await _write_day(db, day, await current_counts(db))
    await db.commit()
    logger.info(f"Unclassified snapshot {day}: {written}")
    return written


async def history(db: AsyncSession, days: int = 90) -> list[dict]:
    """[{date, total_rules, fields: {field: count}}] oldest first."""
    since = utcnow().date() - timedelta(days=days)
    rows = (
        await db.execute(
            select(
                UnclassifiedSnapshot.snapshot_date,
                UnclassifiedSnapshot.field,
                func.sum(UnclassifiedSnapshot.rule_count),
                func.sum(UnclassifiedSnapshot.total_rules),
            )
            .where(UnclassifiedSnapshot.snapshot_date >= since)
            .group_by(UnclassifiedSnapshot.snapshot_date, UnclassifiedSnapshot.field)
            .order_by(UnclassifiedSnapshot.snapshot_date)
        )
    ).all()
    by_day: dict[date, dict] = {}
    for day, field, count, total in rows:
        entry = by_day.setdefault(day, {"date": day.isoformat(), "total_rules": 0, "fields": {}})
        entry["fields"][field] = int(count or 0)
        # total_rules is summed per field row; every field carries the
        # same per-source total, so any one field's sum is the corpus.
        entry["total_rules"] = int(total or 0)
    return list(by_day.values())


async def build_report(db: AsyncSession) -> dict:
    """The /methodology/unclassified payload."""
    counts = await current_counts(db)
    fields = list(UNCLASSIFIED_FIELDS)
    sources = []
    totals: dict[str, int] = defaultdict(int)
    grand = 0
    for source in sorted(counts):
        c = counts[source]
        grand += c.get("_total", 0)
        for f in fields:
            totals[f] += c.get(f, 0)
        sources.append({
            "source": source,
            "total_rules": c.get("_total", 0),
            "fields": {f: c.get(f, 0) for f in fields},
        })
    return {
        "generated_at": utcnow().isoformat(),
        "fields": fields,
        "catalog_filter_key": CATALOG_FILTER_KEY,
        "total_rules": grand,
        "totals": {f: totals[f] for f in fields},
        "sources": sources,
        "history": await history(db),
    }

