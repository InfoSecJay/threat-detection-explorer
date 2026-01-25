"""Trending data API routes."""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, String, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection

router = APIRouter(prefix="/trending", tags=["trending"])


@router.get("/techniques")
async def get_trending_techniques(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of techniques to return"),
    db: AsyncSession = Depends(get_db),
):
    """Get trending MITRE techniques based on recently created/modified rules.

    Returns techniques ordered by the number of rules created/modified in the time period.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get all detections modified/created after cutoff date
    query = select(Detection).where(
        and_(
            Detection.rule_modified_date.isnot(None),
            Detection.rule_modified_date >= cutoff_date,
        )
    )

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
    db: AsyncSession = Depends(get_db),
):
    """Get trending platforms based on recently created/modified rules.

    Returns platforms ordered by the number of rules created/modified in the time period.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get all detections modified/created after cutoff date
    query = select(Detection).where(
        and_(
            Detection.rule_modified_date.isnot(None),
            Detection.rule_modified_date >= cutoff_date,
            Detection.platform.isnot(None),
            Detection.platform != "",
        )
    )

    result = await db.execute(query)
    detections = result.scalars().all()

    # Count platforms
    platform_counts: dict[str, dict] = {}
    for detection in detections:
        platform = detection.platform
        if not platform:
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

        # Track the most recent rule date for this platform
        if detection.rule_modified_date:
            current_latest = platform_counts[platform]["latest_date"]
            if current_latest is None or detection.rule_modified_date > current_latest:
                platform_counts[platform]["latest_date"] = detection.rule_modified_date

    # Sort by count and return top N
    sorted_platforms = sorted(
        platform_counts.values(),
        key=lambda x: (-x["count"], x["platform"]),
    )[:limit]

    # Convert sets to lists and format dates
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
    for source in ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm"]:
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
