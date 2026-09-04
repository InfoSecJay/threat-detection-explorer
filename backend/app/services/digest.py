"""Weekly digest: one document that says what changed in the corpus.

Composes signals the site already computes -- per-source net deltas
(sync-job history), techniques newly covered (coverage snapshots / rule
dates), technique momentum (snapshots), the newest rules, and the data
sources gaining rules -- into a single, dated, shareable object. The
/digest page renders it; the RSS feeds are derived from the same
queries so subscribers and the page never disagree.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional
import re
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.removed_detection import RemovedDetection
from app.services.corpus_cache import corpus_cache
from app.services.coverage_snapshot import compute_newly_covered
from app.services.mitre import mitre_service
from app.services.source_deltas import compute_source_deltas
from app.services.technique_deltas import compute_technique_deltas
from app.utils.datetime_utils import to_utc_iso, utcnow

# Bump when the payload gains or renames a field. The weekly digests are
# persisted artifacts keyed on the corpus fingerprint, so without this a
# deploy that adds a field keeps serving the old shape until the next
# sync -- which is how `removed_rules` crashed the page on 2026-09-04.
_DIGEST_SHAPE_VERSION = 2

_RULE_COLS = (
    Detection.id, Detection.rule_id, Detection.title, Detection.source,
    Detection.severity, Detection.status, Detection.platforms, Detection.event_types,
    Detection.mitre_techniques, Detection.quality_score, Detection.source_rule_url,
    Detection.rule_created_date, Detection.rule_modified_date, Detection.description,
)


def _rule_dict(row) -> dict:
    return {
        "id": row[0],
        "rule_id": row[1],
        "title": row[2],
        "source": row[3],
        "severity": row[4],
        "status": row[5],
        "platforms": row[6] or [],
        "event_types": row[7] or [],
        "mitre_techniques": row[8] or [],
        "quality_score": row[9],
        "source_rule_url": row[10],
        "created": to_utc_iso(row[11]),
        "modified": to_utc_iso(row[12]),
        "description": (row[13] or "")[:400],
    }


def _created_in(since, until=None):
    # Deprecated rules never belong in the digest (teardown R11 / #109).
    cond = and_(
        Detection.rule_created_date.isnot(None),
        Detection.rule_created_date >= since,
        Detection.status != "deprecated",
    )
    if until is not None:
        cond = and_(cond, Detection.rule_created_date < until)
    return cond


def _modified_in(since, until=None):
    """Changed in the window but NOT created in it -- a brand-new rule
    also carries a modified date and must not be counted twice."""
    cond = and_(
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= since,
        or_(Detection.rule_created_date.is_(None), Detection.rule_created_date < since),
        Detection.status != "deprecated",
    )
    if until is not None:
        cond = and_(cond, Detection.rule_modified_date < until)
    return cond


def parse_iso_week(week: str) -> tuple[datetime, datetime]:
    """`2026-w35` -> (Monday 00:00 UTC, next Monday 00:00 UTC).

    Raises ValueError on malformed input or a week in the future.
    Permanent digest URLs (#91 / teardown F16) hang off these windows.
    """
    m = re.fullmatch(r"(\d{4})-[wW](\d{1,2})", (week or "").strip())
    if not m:
        raise ValueError(f"invalid week {week!r}; expected e.g. 2026-w35")
    year, wk = int(m.group(1)), int(m.group(2))
    if not 1 <= wk <= 53:
        raise ValueError(f"invalid week number {wk}")
    try:
        start = datetime.fromisocalendar(year, wk, 1)
    except ValueError as e:
        raise ValueError(f"invalid week {week!r}: {e}") from e
    if start > utcnow():
        raise ValueError(f"week {week!r} is in the future")
    return start, start + timedelta(days=7)


def iso_week_label(dt: datetime) -> str:
    y, w, _ = dt.isocalendar()
    return f"{y}-w{w:02d}"


async def new_rules(db: AsyncSession, *, since, limit: int, source: Optional[str] = None, until=None) -> list[dict]:
    cond = _created_in(since, until)
    if source:
        cond = and_(cond, Detection.source == source)
    rows = (
        await db.execute(
            select(*_RULE_COLS).where(cond)
            .order_by(Detection.rule_created_date.desc(), Detection.title.asc())
            .limit(limit)
        )
    ).all()
    return [_rule_dict(r) for r in rows]


async def modified_rules(db: AsyncSession, *, since, limit: int, source: Optional[str] = None, until=None) -> list[dict]:
    cond = _modified_in(since, until)
    if source:
        cond = and_(cond, Detection.source == source)
    rows = (
        await db.execute(
            select(*_RULE_COLS).where(cond)
            .order_by(Detection.rule_modified_date.desc(), Detection.title.asc())
            .limit(limit)
        )
    ).all()
    return [_rule_dict(r) for r in rows]


def _removed_in(since, until=None, source: Optional[str] = None):
    """Tombstones in the window whose rule is really gone.

    A tombstone is written whenever a row is deleted, and rows get
    deleted for reasons other than an upstream removal: the permalink
    re-keying (#86) tombstoned every rule under its old id on
    2026-08-31, and the 2026-09-02 volume incident tombstoned 176 live
    Splunk rules that came back the next night. So a removal only counts
    when no live rule carries the tombstone's id or its upstream
    (source, rule_id).
    """
    from app.services.tombstones import shadowed_by_live_rule

    cond = and_(RemovedDetection.removed_at >= since, ~shadowed_by_live_rule())
    if until is not None:
        cond = and_(cond, RemovedDetection.removed_at < until)
    if source:
        cond = and_(cond, RemovedDetection.source == source)
    return cond


def _removal_key():
    """One removal per upstream rule: a rule re-keyed (#86) and later
    removed leaves two tombstones (old id, new id) for one event."""
    return func.coalesce(RemovedDetection.source + ":" + RemovedDetection.rule_id, RemovedDetection.id)


async def count_removed(db: AsyncSession, *, since, until=None) -> int:
    return (
        await db.execute(select(func.count(func.distinct(_removal_key()))).where(_removed_in(since, until)))
    ).scalar() or 0


async def removed_rules(db: AsyncSession, *, since, limit: int, source: Optional[str] = None, until=None) -> list[dict]:
    """Rules that vanished upstream in the window (#87 tombstones).

    Every parser skips `deprecated/` folders and Elastic's deprecated
    maturity, so an upstream deprecation reaches the corpus as a
    removal, not as `status: deprecated` -- this list is the digest's
    "retired this week". `removed_at` is when the nightly sync noticed,
    i.e. the morning after the upstream commit.
    """
    rows = (
        await db.execute(
            select(
                RemovedDetection.id, RemovedDetection.rule_id, RemovedDetection.title,
                RemovedDetection.source, RemovedDetection.severity, RemovedDetection.mitre_techniques,
                RemovedDetection.first_seen_at, RemovedDetection.removed_at,
            )
            .where(_removed_in(since, until, source))
            .order_by(RemovedDetection.removed_at.desc(), RemovedDetection.title.asc())
            # Over-fetch so the de-duplication below can still fill `limit`.
            .limit(limit * 3)
        )
    ).all()
    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        key = f"{r[3]}:{r[1]}" if r[1] else r[0]
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "id": r[0],
            "rule_id": r[1],
            "title": r[2],
            "source": r[3],
            "severity": r[4] or "unknown",
            "mitre_techniques": [t for t in (r[5] or []) if isinstance(t, str)],
            "first_seen": to_utc_iso(r[6]),
            "removed": to_utc_iso(r[7]),
        })
        if len(out) >= limit:
            break
    return out


def _themes(rules: list[dict], limit: int = 8) -> list[dict]:
    """The techniques the new rules cluster on -- the data-driven "key
    takeaways": technique, tactic, how many new rules, from which
    sources, and a few of them by name."""
    counts: Counter[str] = Counter()
    sources: dict[str, Counter[str]] = defaultdict(Counter)
    samples: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        for tid in dict.fromkeys(t.upper() for t in r["mitre_techniques"] if isinstance(t, str) and t):
            counts[tid] += 1
            sources[tid][r["source"]] += 1
            if len(samples[tid]) < 3:
                samples[tid].append({"id": r["id"], "title": r["title"], "source": r["source"]})
    out = []
    for tid, n in counts.most_common(limit):
        info = mitre_service.get_technique(tid) or {}
        tactic_ids = info.get("tactics") or []
        tactic = mitre_service.get_tactic(tactic_ids[0]) if tactic_ids else None
        out.append({
            "technique_id": tid,
            "technique_name": info.get("name", ""),
            "tactic": (tactic or {}).get("name", ""),
            "rules": n,
            "sources": dict(sources[tid].most_common()),
            "samples": samples[tid],
        })
    return out


async def compute_digest(
    db: AsyncSession,
    days: int = 7,
    limit: int = 15,
    rules_limit: int = 300,
    week: Optional[str] = None,
) -> dict:
    """Digest payload, memoised on the corpus fingerprint.

    Rolling mode (default): last `days`, keyed with the UTC date since
    the window is anchored to "now". Week mode (#91): `week` like
    `2026-w35` pins the window to that ISO week -- a permanent,
    citable URL whose content does not roll (no date in the key).
    Raises ValueError for malformed/future weeks (route -> 400).
    """
    if week is not None:
        start, end = parse_iso_week(week)
        key = ("digest-week", f"v{_DIGEST_SHAPE_VERSION}", week, limit, rules_limit)
        return await corpus_cache.get(
            db, key,
            lambda: _compute_digest(db, 7, limit, rules_limit, start=start, end=end, week=week.lower()),
            persist=True,
        )
    key = ("digest", f"v{_DIGEST_SHAPE_VERSION}", days, limit, rules_limit, utcnow().date().isoformat())
    return await corpus_cache.get(db, key, lambda: _compute_digest(db, days, limit, rules_limit), persist=True)


async def _compute_digest(db: AsyncSession, days: int, limit: int, rules_limit: int, start=None, end=None, week: Optional[str] = None) -> dict:
    if end is None:
        end = utcnow()
    if start is None:
        start = end - timedelta(days=days)
    until = end if week is not None else None

    async def _count(cond) -> int:
        return (await db.execute(select(func.count(Detection.id)).where(cond))).scalar() or 0

    async def _count_by_source(cond) -> dict[str, int]:
        rows = (
            await db.execute(select(Detection.source, func.count(Detection.id)).where(cond).group_by(Detection.source))
        ).all()
        return {src: int(n) for src, n in rows}

    total_rules = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    created = await _count(_created_in(start, until))
    modified = await _count(_modified_in(start, until))
    created_by = await _count_by_source(_created_in(start, until))
    modified_by = await _count_by_source(_modified_in(start, until))
    by_source = {
        src: {"created": created_by.get(src, 0), "modified": modified_by.get(src, 0)}
        for src in sorted(set(created_by) | set(modified_by), key=lambda s: (-created_by.get(s, 0), -modified_by.get(s, 0), s))
    }

    # Emerging data sources: canonical data_sources by new-rule volume.
    ds_rows = (
        await db.execute(
            select(Detection.source, Detection.data_sources).where(
                and_(Detection.rule_created_date.isnot(None), Detection.rule_created_date >= start)
            )
        )
    ).all()
    ds_counts: dict[str, dict] = {}
    for source, data_sources in ds_rows:
        for ds in data_sources or []:
            if not isinstance(ds, str) or not ds or ds == "unknown":
                continue
            entry = ds_counts.setdefault(ds, {"data_source": ds, "count": 0, "sources": set()})
            entry["count"] += 1
            entry["sources"].add(source)
    emerging = [
        {"data_source": e["data_source"], "count": e["count"], "sources": sorted(e["sources"])}
        for e in sorted(ds_counts.values(), key=lambda x: (-x["count"], x["data_source"]))[:10]
    ]

    source_deltas = await compute_source_deltas(db, days=days)
    newly_covered = await compute_newly_covered(db, days=days, limit=limit)
    momentum = await compute_technique_deltas(db, days=days, limit=8)
    rules = await new_rules(db, since=start, limit=rules_limit, until=until)
    changed = await modified_rules(db, since=start, limit=rules_limit, until=until)
    gone = await removed_rules(db, since=start, limit=rules_limit, until=until)
    removed_total = await count_removed(db, since=start, until=until)

    return {
        "generated_at": to_utc_iso(end),
        "period": {
            "days": days,
            "start": to_utc_iso(start),
            "end": to_utc_iso(end),
            "week": week,
            "this_week": iso_week_label(utcnow()),
        },
        "summary": {
            "total_rules": total_rules,
            "created": created,
            "modified": modified,
            # Removed upstream in the window (tombstoned), all sources.
            "removed": removed_total,
            # Kept for older clients; by_source carries both counts.
            "created_by_source": {s: v["created"] for s, v in by_source.items() if v["created"]},
            "by_source": by_source,
        },
        "themes": _themes(rules),
        "source_deltas": source_deltas,
        "newly_covered": newly_covered,
        "momentum": momentum,
        "new_rules": rules,
        "modified_rules": changed,
        "removed_rules": gone,
        "emerging_data_sources": emerging,
    }


# -- RSS ------------------------------------------------------------------------


def _rss(title: str, link: str, description: str, items: list[dict]) -> str:
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
        "<channel>",
        f"<title>{escape(title)}</title>",
        f"<link>{escape(link)}</link>",
        f"<description>{escape(description)}</description>",
        f"<lastBuildDate>{utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}</lastBuildDate>",
    ]
    for it in items:
        parts.append("<item>")
        parts.append(f"<title>{escape(it['title'])}</title>")
        parts.append(f"<link>{escape(it['link'])}</link>")
        parts.append(f"<guid isPermaLink=\"false\">{escape(it['guid'])}</guid>")
        if it.get("pub_date"):
            parts.append(f"<pubDate>{escape(it['pub_date'])}</pubDate>")
        parts.append(f"<description>{escape(it['description'])}</description>")
        for cat in it.get("categories", []):
            parts.append(f"<category>{escape(cat)}</category>")
        parts.append("</item>")
    parts.append("</channel></rss>")
    return "\n".join(parts)


def _rfc822(iso: str | None) -> str | None:
    if not iso:
        return None
    from datetime import datetime

    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def _rule_items(rules: list[dict], site_url: str, date_key: str) -> list[dict]:
    return [
        {
            "title": f"[{r['source']}] {r['title']}",
            "link": f"{site_url}/detections/{r['id']}",
            # New-rule guids stay stable (subscribers already have them);
            # an update is a new event, so its guid carries the date.
            "guid": f"detection:{r['id']}" if date_key == "created" else f"detection:{r['id']}:modified:{r['modified'] or ''}",
            "pub_date": _rfc822(r[date_key]),
            "description": (
                f"{r['description'] or 'No description.'} "
                f"(severity {r['severity']}, techniques {', '.join(r['mitre_techniques']) or 'none'}"
                f"{', hygiene ' + str(r['quality_score']) if r['quality_score'] is not None else ''})"
            ),
            "categories": [r["source"], *r["mitre_techniques"][:5]],
        }
        for r in rules
    ]


async def new_rules_feed(
    db: AsyncSession, site_url: str, *, days: int = 30, limit: int = 50, source: Optional[str] = None,
) -> str:
    rules = await new_rules(db, since=utcnow() - timedelta(days=days), limit=limit, source=source)
    scope = f"from {source}" if source else "across every tracked source"
    return _rss(
        f"Detection Explorer - new detection rules{' (' + source + ')' if source else ''}",
        f"{site_url}/digest",
        f"Detection rules added to the corpus in the last {days} days, {scope}.",
        _rule_items(rules, site_url, "created"),
    )


async def modified_rules_feed(
    db: AsyncSession, site_url: str, *, days: int = 30, limit: int = 50, source: Optional[str] = None,
) -> str:
    rules = await modified_rules(db, since=utcnow() - timedelta(days=days), limit=limit, source=source)
    scope = f"from {source}" if source else "across every tracked source"
    return _rss(
        f"Detection Explorer - updated detection rules{' (' + source + ')' if source else ''}",
        f"{site_url}/digest",
        f"Existing detection rules changed upstream in the last {days} days, {scope}.",
        _rule_items(rules, site_url, "modified"),
    )


async def newly_covered_feed(db: AsyncSession, site_url: str, *, days: int = 30, limit: int = 50) -> str:
    data = await compute_newly_covered(db, days=days, limit=limit)
    items = []
    for e in data.get("catalog_newly_covered", []):
        srcs = ", ".join(sorted(e.get("sources", {}).keys()))
        items.append({
            "title": f"{e['technique_id']} {e.get('technique_name', '')} - first rule in the catalog",
            "link": f"{site_url}/mitre/{e['technique_id']}",
            "guid": f"newly-covered:catalog:{e['technique_id']}:{data.get('baseline_date') or days}",
            "pub_date": None,
            "description": f"Now covered by {srcs} ({e.get('total_rules', 0)} rule(s)).",
            "categories": [e["technique_id"], *sorted(e.get("sources", {}).keys())],
        })
    for e in data.get("source_newly_covered", []):
        items.append({
            "title": f"{e['technique_id']} {e.get('technique_name', '')} - new for {e['source']}",
            "link": f"{site_url}/mitre/{e['technique_id']}",
            "guid": f"newly-covered:{e['source']}:{e['technique_id']}:{data.get('baseline_date') or days}",
            "pub_date": None,
            "description": (
                f"{e['source']} added {e.get('rule_count', 0)} rule(s); already covered by "
                f"{', '.join(e.get('covered_elsewhere', [])) or 'no other source'}."
            ),
            "categories": [e["technique_id"], e["source"]],
        })
    return _rss(
        "Detection Explorer - techniques newly covered",
        f"{site_url}/digest",
        f"ATT&CK techniques that gained detection coverage in the last {days} days (method: {data.get('method')}).",
        items,
    )
