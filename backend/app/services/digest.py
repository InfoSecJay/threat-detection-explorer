"""Weekly digest: one document that says what changed in the corpus.

Composes signals the site already computes -- per-source net deltas
(sync-job history), techniques newly covered (coverage snapshots / rule
dates), technique momentum (snapshots), the newest rules, and the data
sources gaining rules -- into a single, dated, shareable object. The
/digest page renders it; the RSS feeds are derived from the same
queries so subscribers and the page never disagree.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from xml.sax.saxutils import escape

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.coverage_snapshot import compute_newly_covered
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


async def new_rules(db: AsyncSession, *, since, limit: int) -> list[dict]:
    rows = (
        await db.execute(
            select(*_RULE_COLS)
            .where(and_(Detection.rule_created_date.isnot(None), Detection.rule_created_date >= since))
            .order_by(Detection.rule_created_date.desc(), Detection.title.asc())
            .limit(limit)
        )
    ).all()
    return [_rule_dict(r) for r in rows]


async def compute_digest(db: AsyncSession, days: int = 7, limit: int = 15) -> dict:
    end = utcnow()
    start = end - timedelta(days=days)

    async def _count(col) -> int:
        return (
            await db.execute(select(func.count(Detection.id)).where(and_(col.isnot(None), col >= start)))
        ).scalar() or 0

    total_rules = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    created = await _count(Detection.rule_created_date)
    modified = await _count(Detection.rule_modified_date)

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
    rules = await new_rules(db, since=start, limit=limit)

    # Per-source new-rule counts for the header strip.
    by_source: dict[str, int] = defaultdict(int)
    src_rows = (
        await db.execute(
            select(Detection.source, func.count(Detection.id))
            .where(and_(Detection.rule_created_date.isnot(None), Detection.rule_created_date >= start))
            .group_by(Detection.source)
        )
    ).all()
    for source, n in src_rows:
        by_source[source] = int(n)

    return {
        "generated_at": to_utc_iso(end),
        "period": {"days": days, "start": to_utc_iso(start), "end": to_utc_iso(end)},
        "summary": {
            "total_rules": total_rules,
            "created": created,
            "modified": modified,
            "created_by_source": dict(sorted(by_source.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        "source_deltas": source_deltas,
        "newly_covered": newly_covered,
        "momentum": momentum,
        "new_rules": rules,
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


async def new_rules_feed(db: AsyncSession, site_url: str, *, days: int = 30, limit: int = 50) -> str:
    rules = await new_rules(db, since=utcnow() - timedelta(days=days), limit=limit)
    items = [
        {
            "title": f"[{r['source']}] {r['title']}",
            "link": f"{site_url}/detections/{r['id']}",
            "guid": f"detection:{r['id']}",
            "pub_date": _rfc822(r["created"]),
            "description": (
                f"{r['description'] or 'No description.'} "
                f"(severity {r['severity']}, techniques {', '.join(r['mitre_techniques']) or 'none'}"
                f"{', hygiene ' + str(r['quality_score']) if r['quality_score'] is not None else ''})"
            ),
            "categories": [r["source"], *r["mitre_techniques"][:5]],
        }
        for r in rules
    ]
    return _rss(
        "Detection Explorer - new detection rules",
        f"{site_url}/digest",
        f"Detection rules added to the corpus in the last {days} days, across every tracked source.",
        items,
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
