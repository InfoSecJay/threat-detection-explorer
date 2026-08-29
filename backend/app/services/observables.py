"""Observable pages: everything the corpus knows about one extracted
value (a process name, event ID, file path, registry key, network
indicator, API action, source table, or target resource).

Each surface maps to one `extracted_*` JSON-list column. Matching is
whole-element, case-insensitive (`%"value"%` on the JSON text -- the
same semantics as the query bar's `process:` / `eventid:` fields), so
`mimikatz.exe` does not match `notmimikatz.exe`.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection

# URL segment -> (column, SearchFilters key for the catalog link, label)
OBSERVABLE_TYPES: dict[str, tuple[str, str, str]] = {
    "process": ("extracted_process_names", "process_names", "Process"),
    "path": ("extracted_file_paths", "file_paths", "File path"),
    "registry": ("extracted_registry_keys", "registry_keys", "Registry key"),
    "network": ("extracted_network_indicators", "network_indicators", "Network indicator"),
    "action": ("extracted_api_actions", "api_actions", "API action"),
    "eventid": ("extracted_event_ids", "event_ids", "Event ID"),
    "table": ("extracted_source_tables", "source_tables", "Source table"),
    "resource": ("extracted_target_resources", "target_resources", "Target resource"),
}

_CO_OCCUR_SURFACES = ("process", "eventid", "action", "table", "path", "registry", "network")


def _column(kind: str):
    return getattr(Detection, OBSERVABLE_TYPES[kind][0])


def _contains(kind: str, value: str):
    escaped = value.replace("%", "\\%").replace("_", "\\_")
    return cast(_column(kind), String).ilike(f'%"{escaped}"%', escape="\\")


async def top_values(db: AsyncSession, kind: str, limit: int = 100, source: Optional[str] = None) -> dict:
    """Most common values on one surface, with rule + source counts."""
    query = select(Detection.source, _column(kind))
    if source:
        query = query.where(Detection.source == source)
    rows = (await db.execute(query)).all()
    counts: Counter[str] = Counter()
    sources: dict[str, set[str]] = defaultdict(set)
    canonical: dict[str, str] = {}
    for src, values in rows:
        for v in values or []:
            if not isinstance(v, str) or not v.strip():
                continue
            key = v.lower()
            canonical.setdefault(key, v)
            counts[key] += 1
            sources[key].add(src)
    return {
        "type": kind,
        "label": OBSERVABLE_TYPES[kind][2],
        "distinct": len(counts),
        "values": [
            {"value": canonical[k], "rules": n, "sources": sorted(sources[k])}
            for k, n in counts.most_common(limit)
        ],
    }


async def observable_profile(db: AsyncSession, kind: str, value: str, sample_limit: int = 50) -> dict:
    rows = (
        await db.execute(
            select(
                Detection.id, Detection.title, Detection.source, Detection.severity, Detection.status,
                Detection.mitre_techniques, Detection.mitre_tactics, Detection.platforms,
                Detection.quality_score, Detection.rule_created_date,
                *[_column(k) for k in _CO_OCCUR_SURFACES],
                Detection.extracted_observables,
            ).where(_contains(kind, value)).order_by(Detection.source.asc(), Detection.title.asc())
        )
    ).all()

    by_source: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_technique: Counter[str] = Counter()
    by_tactic: Counter[str] = Counter()
    by_platform: Counter[str] = Counter()
    co: dict[str, Counter[str]] = {k: Counter() for k in _CO_OCCUR_SURFACES}
    negated_in = 0
    fields: Counter[str] = Counter()
    samples: list[dict] = []
    value_l = value.lower()

    for r in rows:
        rid, title, source, severity, status, techs, tactics, platforms, quality, created = r[:10]
        by_source[source] += 1
        by_severity[severity or "unknown"] += 1
        for t in techs or []:
            by_technique[t] += 1
        for t in tactics or []:
            by_tactic[t] += 1
        for p in platforms or []:
            if p and p != "unknown":
                by_platform[p] += 1
        for k, vals in zip(_CO_OCCUR_SURFACES, r[10:10 + len(_CO_OCCUR_SURFACES)]):
            for v in vals or []:
                if isinstance(v, str) and v and not (k == kind and v.lower() == value_l):
                    co[k][v] += 1
        # Which field named it, and whether any rule uses it as an exclusion.
        for o in r[10 + len(_CO_OCCUR_SURFACES)] or []:
            if not isinstance(o, dict):
                continue
            if any(isinstance(x, str) and x.lower() == value_l for x in (o.get("values") or [])):
                fields[o.get("field") or "?"] += 1
                if o.get("negated"):
                    negated_in += 1
                    break
        if len(samples) < sample_limit:
            samples.append({
                "id": rid, "title": title, "source": source, "severity": severity, "status": status,
                "mitre_techniques": techs or [], "quality_score": quality,
                "created": created.isoformat() + "Z" if created else None,
            })

    col, filter_key, label = OBSERVABLE_TYPES[kind]
    return {
        "type": kind,
        "label": label,
        "value": value,
        "filter_key": filter_key,
        "total_rules": len(rows),
        "negated_in": negated_in,
        "by_source": dict(by_source.most_common()),
        "by_severity": dict(by_severity.most_common()),
        "by_platform": dict(by_platform.most_common(8)),
        "by_technique": [{"technique_id": t, "rules": n} for t, n in by_technique.most_common(15)],
        "by_tactic": [{"tactic_id": t, "rules": n} for t, n in by_tactic.most_common(8)],
        "fields": [{"field": f, "rules": n} for f, n in fields.most_common(8)],
        "co_occurring": {
            k: [{"value": v, "rules": n} for v, n in c.most_common(8)]
            for k, c in co.items() if c
        },
        "rules": samples,
    }


async def count_rules(db: AsyncSession, kind: str, value: str) -> int:
    return (await db.execute(select(func.count(Detection.id)).where(_contains(kind, value)))).scalar() or 0
