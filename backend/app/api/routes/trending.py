"""Trending data API routes."""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, String, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.repository_sync import ALL_REPOSITORY_NAMES

router = APIRouter(prefix="/trending", tags=["trending"])


def _parse_csv(raw: Optional[str]) -> list[str]:
    """Split a comma-separated query value into a trimmed list."""
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _apply_trending_filters(
    conditions: list,
    sources: list[str],
    platforms: list[str],
    event_types: list[str],
) -> None:
    """Append source / platform / event-type filters to a condition list.

    Shared between all three trending endpoints so the filter semantics
    stay identical: source is an exact-match on the enum column, while
    platform + event_type use the same JSON-array `ilike` trick the
    search service uses (portable across SQLite + Postgres).
    """
    if sources:
        conditions.append(Detection.source.in_(sources))
    if platforms:
        plat_conds = [
            cast(Detection.taxonomy_platforms, String).ilike(f'%"{v}"%')
            for v in platforms
        ]
        conditions.append(or_(*plat_conds))
    if event_types:
        et_conds = [
            cast(Detection.taxonomy_event_types, String).ilike(f'%"{v}"%')
            for v in event_types
        ]
        conditions.append(or_(*et_conds))


@router.get("/techniques")
async def get_trending_techniques(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of techniques to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    platforms: Optional[str] = Query(None, description="Comma-separated canonical-platform filter (e.g. 'o365,windows')"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Get trending MITRE techniques based on recently created/modified rules.

    Returns techniques ordered by the number of rules created/modified in the time period.
    Optional filters narrow the corpus before counting (e.g. "top techniques in new O365 rules").
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), _parse_csv(platforms), _parse_csv(event_types))

    query = select(Detection).where(and_(*conditions))

    result = await db.execute(query)
    detections = result.scalars().all()

    # Count techniques
    technique_counts: dict[str, dict] = {}
    for detection in detections:
        for technique in detection.mitre_techniques:
            if technique not in technique_counts:
                technique_counts[technique] = {
                    "technique_id": technique,
                    "count": 0,
                    "sources": set(),
                    "latest_date": None,
                }
            technique_counts[technique]["count"] += 1
            technique_counts[technique]["sources"].add(detection.source)

            # Track the most recent rule date for this technique
            if detection.rule_modified_date:
                current_latest = technique_counts[technique]["latest_date"]
                if current_latest is None or detection.rule_modified_date > current_latest:
                    technique_counts[technique]["latest_date"] = detection.rule_modified_date

    # Sort by count and return top N
    sorted_techniques = sorted(
        technique_counts.values(),
        key=lambda x: (-x["count"], x["technique_id"]),
    )[:limit]

    # Convert sets to lists and format dates
    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "count": t["count"],
                "sources": list(t["sources"]),
                "latest_date": t["latest_date"].isoformat() if t["latest_date"] else None,
            }
            for t in sorted_techniques
        ],
    }


@router.get("/platforms")
async def get_trending_platforms(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of platforms to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Get trending platforms based on recently created/modified rules.

    Reads the canonical `taxonomy_platforms` array column so multi-OS
    rules count toward every platform they target (a rule tagged
    [windows, linux] counts for both). The `unknown` sentinel is
    filtered out so it doesn't dominate. Note: a `platforms` filter
    here would be circular (it's the grouping key), so only source +
    event_type are exposed.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), [], _parse_csv(event_types))

    query = select(Detection).where(and_(*conditions))

    result = await db.execute(query)
    detections = result.scalars().all()

    platform_counts: dict[str, dict] = {}
    for detection in detections:
        platforms = detection.taxonomy_platforms or []
        for platform in platforms:
            if not platform or platform == "unknown":
                continue
            if platform not in platform_counts:
                platform_counts[platform] = {
                    "platform": platform,
                    "count": 0,
                    "sources": set(),
                    "latest_date": None,
                }
            platform_counts[platform]["count"] += 1
            platform_counts[platform]["sources"].add(detection.source)

            if detection.rule_modified_date:
                current_latest = platform_counts[platform]["latest_date"]
                if current_latest is None or detection.rule_modified_date > current_latest:
                    platform_counts[platform]["latest_date"] = detection.rule_modified_date

    sorted_platforms = sorted(
        platform_counts.values(),
        key=lambda x: (-x["count"], x["platform"]),
    )[:limit]

    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "platforms": [
            {
                "platform": p["platform"],
                "count": p["count"],
                "sources": list(p["sources"]),
                "latest_date": p["latest_date"].isoformat() if p["latest_date"] else None,
            }
            for p in sorted_platforms
        ],
    }


@router.get("/recent-rules")
async def get_recent_rules(
    limit: int = Query(20, ge=5, le=50, description="Number of rules per list"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    platforms: Optional[str] = Query(None, description="Comma-separated canonical-platform filter (e.g. 'o365,windows')"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recently created + most recently modified rules.

    Two parallel lists, each ordered by the respective date descending.
    Powers the "Recent activity" section of the Intel page. Rules
    without a date stamp are excluded (would pollute the top of the
    list with deterministic-but-meaningless ordering). Optional filters
    narrow the corpus (e.g. sources=sigma&platforms=o365).
    """
    def _format(d: Detection, date_field: str) -> dict:
        date_value = getattr(d, date_field, None)
        return {
            "id": d.id,
            "rule_id": d.rule_id,
            "title": d.title,
            "source": d.source,
            "severity": d.severity,
            "platforms": d.taxonomy_platforms or [],
            "event_types": d.taxonomy_event_types or [],
            "date": date_value.isoformat() if date_value else None,
        }

    src_list = _parse_csv(sources)
    plat_list = _parse_csv(platforms)
    et_list = _parse_csv(event_types)

    created_conds = [Detection.rule_created_date.isnot(None)]
    _apply_trending_filters(created_conds, src_list, plat_list, et_list)
    created_q = (
        select(Detection)
        .where(and_(*created_conds))
        .order_by(Detection.rule_created_date.desc())
        .limit(limit)
    )

    modified_conds = [Detection.rule_modified_date.isnot(None)]
    _apply_trending_filters(modified_conds, src_list, plat_list, et_list)
    modified_q = (
        select(Detection)
        .where(and_(*modified_conds))
        .order_by(Detection.rule_modified_date.desc())
        .limit(limit)
    )

    created = (await db.execute(created_q)).scalars().all()
    modified = (await db.execute(modified_q)).scalars().all()

    return {
        "most_recently_created": [_format(d, "rule_created_date") for d in created],
        "most_recently_modified": [_format(d, "rule_modified_date") for d in modified],
    }


@router.get("/summary")
async def get_trending_summary(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    db: AsyncSession = Depends(get_db),
):
    """Get a summary of recent activity across all sources."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Count total rules modified in period
    total_query = select(func.count(Detection.id)).where(
        and_(
            Detection.rule_modified_date.isnot(None),
            Detection.rule_modified_date >= cutoff_date,
        )
    )
    total_result = await db.execute(total_query)
    total_modified = total_result.scalar() or 0

    # Count by source
    by_source = {}
    for source in ALL_REPOSITORY_NAMES:
        source_query = select(func.count(Detection.id)).where(
            and_(
                Detection.source == source,
                Detection.rule_modified_date.isnot(None),
                Detection.rule_modified_date >= cutoff_date,
            )
        )
        source_result = await db.execute(source_query)
        count = source_result.scalar() or 0
        if count > 0:
            by_source[source] = count

    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "total_modified": total_modified,
        "by_source": by_source,
    }
