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
from datetime import timedelta
from xml.sax.saxutils import escape

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.services.coverage_snapshot import compute_newly_covered
from app.services.mitre import mitre_service
from app.services.source_deltas import compute_source_deltas
from app.services.technique_deltas import compute_technique_deltas
from app.utils.datetime_utils import to_utc_iso, utcnow

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


def _created_in(since):
    return and_(Detection.rule_created_date.isnot(None), Detection.rule_created_date >= since)


def _modified_in(since):
    """Changed in the window but NOT created in it -- a brand-new rule
    also carries a modified date and must not be counted twice."""
    return and_(
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= since,
        or_(Detection.rule_created_date.is_(None), Detection.rule_created_date < since),
    )


async def new_rules(db: AsyncSession, *, since, limit: int, source: Optional[str] = None) -> list[dict]:
    cond = _created_in(since)
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


async def modified_rules(db: AsyncSession, *, since, limit: int, source: Optional[str] = None) -> list[dict]:
    cond = _modified_in(since)
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


async def compute_digest(db: AsyncSession, days: int = 7, limit: int = 15, rules_limit: int = 300) -> dict:
    """Weekly digest payload, memoised on the corpus fingerprint plus
    the UTC date (the window is anchored to "now", so the answer can
    change at midnight even when the corpus does not)."""
    key = ("digest", days, limit, rules_limit, utcnow().date().isoformat())
    return await corpus_cache.get(db, key, lambda: _compute_digest(db, days, limit, rules_limit))


async def _compute_digest(db: AsyncSession, days: int, limit: int, rules_limit: int) -> dict:
    end = utcnow()
    start = end - timedelta(days=days)

    async def _count(cond) -> int:
        return (await db.execute(select(func.count(Detection.id)).where(cond))).scalar() or 0

    async def _count_by_source(cond) -> dict[str, int]:
        rows = (
            await db.execute(select(Detection.source, func.count(Detection.id)).where(cond).group_by(Detection.source))
        ).all()
        return {src: int(n) for src, n in rows}

    total_rules = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    created = await _count(_created_in(start))
    modified = await _count(_modified_in(start))
    created_by = await _count_by_source(_created_in(start))
    modified_by = await _count_by_source(_modified_in(start))
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
    rules = await new_rules(db, since=start, limit=rules_limit)
    changed = await modified_rules(db, since=start, limit=rules_limit)

    return {
        "generated_at": to_utc_iso(end),
        "period": {"days": days, "start": to_utc_iso(start), "end": to_utc_iso(end)},
        "summary": {
            "total_rules": total_rules,
            "created": created,
            "modified": modified,
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
