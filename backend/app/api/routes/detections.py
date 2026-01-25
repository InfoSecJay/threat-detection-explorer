"""Detection rules API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.schemas import (
    DetectionResponse,
    DetectionListItem,
    DetectionListResponse,
    SearchParams,
    StatisticsResponse,
)
from app.services.search import SearchService, SearchFilters

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("", response_model=DetectionListResponse)
async def list_detections(
    search: Optional[str] = None,
    sources: Optional[str] = Query(None, description="Comma-separated list of sources"),
    statuses: Optional[str] = Query(None, description="Comma-separated list of statuses"),
    severities: Optional[str] = Query(None, description="Comma-separated list of severities"),
    languages: Optional[str] = Query(None, description="Comma-separated list of rule languages"),
    mitre_tactics: Optional[str] = Query(None, description="Comma-separated list of MITRE tactics"),
    mitre_techniques: Optional[str] = Query(None, description="Comma-separated list of MITRE techniques"),
    tags: Optional[str] = Query(None, description="Comma-separated list of tags"),
    log_sources: Optional[str] = Query(None, description="Comma-separated list of log sources"),
    platforms: Optional[str] = Query(None, description="Comma-separated list of platforms (windows, linux, cloud, etc.)"),
    event_categories: Optional[str] = Query(None, description="Comma-separated list of event categories (process, file, network, etc.)"),
    data_sources_normalized: Optional[str] = Query(None, description="Comma-separated list of normalized data sources (sysmon, auditd, etc.)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("title"),
    sort_order: str = Query("asc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """List detections with filtering and pagination."""
    # Parse comma-separated values
    filters = SearchFilters(
        search=search,
        sources=_parse_csv(sources),
        statuses=_parse_csv(statuses),
        severities=_parse_csv(severities),
        languages=_parse_csv(languages),
        mitre_tactics=_parse_csv(mitre_tactics),
        mitre_techniques=_parse_csv(mitre_techniques),
        tags=_parse_csv(tags),
        log_sources=_parse_csv(log_sources),
        platforms=_parse_csv(platforms),
        event_categories=_parse_csv(event_categories),
        data_sources_normalized=_parse_csv(data_sources_normalized),
        offset=offset,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    search_service = SearchService(db)
    detections, total = await search_service.search_detections(filters)

    return DetectionListResponse(
        items=[DetectionListItem.model_validate(d) for d in detections],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/search", response_model=DetectionListResponse)
async def search_detections(
    params: SearchParams,
    db: AsyncSession = Depends(get_db),
):
    """Search detections with complex filters (POST method for complex queries)."""
    filters = SearchFilters(
        search=params.search,
        sources=params.sources,
        statuses=params.statuses,
        severities=params.severities,
        languages=params.languages,
        mitre_tactics=params.mitre_tactics,
        mitre_techniques=params.mitre_techniques,
        tags=params.tags,
        log_sources=params.log_sources,
        platforms=params.platforms,
        event_categories=params.event_categories,
        data_sources_normalized=params.data_sources_normalized,
        offset=params.offset,
        limit=params.limit,
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )

    search_service = SearchService(db)
    detections, total = await search_service.search_detections(filters)

    return DetectionListResponse(
        items=[DetectionListItem.model_validate(d) for d in detections],
        total=total,
        offset=params.offset,
        limit=params.limit,
    )


@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(db: AsyncSession = Depends(get_db)):
    """Get detection statistics."""
    search_service = SearchService(db)
    stats = await search_service.get_statistics()
    return StatisticsResponse(**stats)


@router.get("/filters")
async def get_filter_options(db: AsyncSession = Depends(get_db)):
    """Get available filter options for dropdowns."""
    search_service = SearchService(db)

    return {
        "sources": await search_service.get_unique_values("source"),
        "statuses": await search_service.get_unique_values("status"),
        "severities": await search_service.get_unique_values("severity"),
        "languages": await search_service.get_unique_values("language"),
    }


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single detection by ID."""
    search_service = SearchService(db)
    detection = await search_service.get_detection_by_id(detection_id)

    if not detection:
        raise HTTPException(status_code=404, detail=f"Detection not found: {detection_id}")

    return DetectionResponse.model_validate(detection)


def _parse_csv(value: Optional[str]) -> list[str]:
    """Parse a comma-separated string into a list."""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
