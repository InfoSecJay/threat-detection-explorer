"""Cross-vendor comparison API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.schemas import (
    CompareRequest, CompareResponse, DetectionListItem,
    SideBySideRequest, SideBySideResponse
)
from app.services.search import SearchService

router = APIRouter(prefix="/compare", tags=["compare"])


@router.get("")
async def compare_detections(
    technique: Optional[str] = Query(None, description="MITRE technique ID (e.g., T1059)"),
    keyword: Optional[str] = Query(None, description="Keyword to search in detection logic"),
    sources: Optional[str] = Query(None, description="Comma-separated list of sources to include"),
    db: AsyncSession = Depends(get_db),
):
    """Compare detections across vendors by technique or keyword.

    Either technique or keyword must be provided.
    """
    if not technique and not keyword:
        raise HTTPException(
            status_code=400,
            detail="Either 'technique' or 'keyword' parameter is required",
        )

    search_service = SearchService(db)
    source_list = [s.strip() for s in sources.split(",")] if sources else None

    if technique:
        # Compare by MITRE technique
        grouped = await search_service.compare_by_technique(technique, source_list)
        query_type = "technique"
        query_value = technique
    else:
        # Compare by keyword
        grouped = await search_service.compare_by_keyword(keyword, source_list)
        query_type = "keyword"
        query_value = keyword

    # Convert to response format
    results = {}
    total_by_source = {}

    for source, detections in grouped.items():
        results[source] = [DetectionListItem.model_validate(d) for d in detections]
        total_by_source[source] = len(detections)

    return CompareResponse(
        query_type=query_type,
        query_value=query_value,
        results=results,
        total_by_source=total_by_source,
    )


@router.post("")
async def compare_detections_post(
    request: CompareRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare detections across vendors (POST method for complex queries)."""
    if not request.technique and not request.keyword:
        raise HTTPException(
            status_code=400,
            detail="Either 'technique' or 'keyword' is required",
        )

    search_service = SearchService(db)
    source_list = request.sources if request.sources else None

    if request.technique:
        grouped = await search_service.compare_by_technique(request.technique, source_list)
        query_type = "technique"
        query_value = request.technique
    else:
        grouped = await search_service.compare_by_keyword(request.keyword, source_list)
        query_type = "keyword"
        query_value = request.keyword

    results = {}
    total_by_source = {}

    for source, detections in grouped.items():
        results[source] = [DetectionListItem.model_validate(d) for d in detections]
        total_by_source[source] = len(detections)

    return CompareResponse(
        query_type=query_type,
        query_value=query_value,
        results=results,
        total_by_source=total_by_source,
    )


@router.get("/coverage-gap")
async def find_coverage_gaps(
    base_source: str = Query(..., description="Source to use as baseline"),
    compare_source: str = Query(..., description="Source to compare against"),
    db: AsyncSession = Depends(get_db),
):
    """Find techniques covered by one source but not another.

    Returns techniques that base_source has detections for,
    but compare_source does not.
    """
    valid_sources = ["sigma", "elastic", "splunk", "sublime", "elastic_protections", "lolrmm"]
    if base_source not in valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid base_source: {base_source}")
    if compare_source not in valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid compare_source: {compare_source}")

    search_service = SearchService(db)

    # Get all techniques from each source
    from app.services.search import SearchFilters
    from sqlalchemy import select
    from app.models.detection import Detection

    # Get unique techniques from base source
    base_filters = SearchFilters(sources=[base_source], limit=10000)
    base_detections, _ = await search_service.search_detections(base_filters)

    base_techniques = set()
    for d in base_detections:
        base_techniques.update(d.mitre_techniques)

    # Get unique techniques from compare source
    compare_filters = SearchFilters(sources=[compare_source], limit=10000)
    compare_detections, _ = await search_service.search_detections(compare_filters)

    compare_techniques = set()
    for d in compare_detections:
        compare_techniques.update(d.mitre_techniques)

    # Find gaps
    gaps = base_techniques - compare_techniques
    overlaps = base_techniques & compare_techniques
    unique_to_compare = compare_techniques - base_techniques

    return {
        "base_source": base_source,
        "compare_source": compare_source,
        "base_technique_count": len(base_techniques),
        "compare_technique_count": len(compare_techniques),
        "overlap_count": len(overlaps),
        "gaps": sorted(list(gaps)),  # In base but not compare
        "unique_to_compare": sorted(list(unique_to_compare)),  # In compare but not base
    }


@router.post("/side-by-side")
async def compare_side_by_side(
    request: SideBySideRequest,
    db: AsyncSession = Depends(get_db),
):
    """Compare 2-6 specific rules side by side.

    Returns the detections along with a field-by-field comparison.
    """
    if len(request.ids) < 2 or len(request.ids) > 6:
        raise HTTPException(
            status_code=400,
            detail="Must provide 2-6 detection IDs for comparison",
        )

    search_service = SearchService(db)
    detections = await search_service.get_detections_by_ids(request.ids)

    if len(detections) < 2:
        raise HTTPException(
            status_code=404,
            detail="At least 2 of the provided detection IDs must exist",
        )

    # Build field comparison
    field_comparison = {
        "title": [d.title for d in detections],
        "source": [d.source for d in detections],
        "severity": [d.severity for d in detections],
        "status": [d.status for d in detections],
        "language": [d.language for d in detections],
        "platform": [d.platform for d in detections],
        "event_category": [d.event_category for d in detections],
        "data_source_normalized": [d.data_source_normalized for d in detections],
        "mitre_tactics": [", ".join(d.mitre_tactics) if d.mitre_tactics else "" for d in detections],
        "mitre_techniques": [", ".join(d.mitre_techniques) if d.mitre_techniques else "" for d in detections],
        "log_sources": [", ".join(d.log_sources) if d.log_sources else "" for d in detections],
        "description": [d.description or "" for d in detections],
        "detection_logic": [d.detection_logic or "" for d in detections],
    }

    return SideBySideResponse(
        detections=[DetectionListItem.model_validate(d) for d in detections],
        field_comparison=field_comparison,
    )
