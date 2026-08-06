"""Detection rules API routes."""

import logging
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

logger = logging.getLogger(__name__)

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
    mitre_groups: Optional[str] = Query(None, description="Comma-separated MITRE ATT&CK Group IDs (e.g. G0016, G1039)"),
    mitre_software: Optional[str] = Query(None, description="Comma-separated MITRE ATT&CK Software IDs (e.g. S0002, S0154)"),
    tags: Optional[str] = Query(None, description="Comma-separated list of tags"),
    platforms: Optional[str] = Query(None, description="Comma-separated list of platforms (windows, linux, cloud, etc.)"),
    event_categories: Optional[str] = Query(None, description="Comma-separated list of event categories (process, file, network, etc.)"),
    data_sources_normalized: Optional[str] = Query(None, description="Comma-separated list of normalized data sources (sysmon, auditd, etc.)"),
    use_cases: Optional[str] = Query(None, description="Comma-separated list of analytic story / use-case labels (e.g. Ransomware, Threat Detection)"),
    event_ids: Optional[str] = Query(None, description="Comma-separated list of extracted Event IDs"),
    process_names: Optional[str] = Query(None, description="Comma-separated list of extracted process names"),
    query_complexity: Optional[str] = Query(None, description="Comma-separated list of query complexity levels (simple, moderate, complex)"),
    api_actions: Optional[str] = Query(None, description="Comma-separated list of API actions (cloud/identity event names)"),
    file_paths: Optional[str] = Query(None, description="Comma-separated list of file-path substrings to match against extracted paths"),
    registry_keys: Optional[str] = Query(None, description="Comma-separated list of registry-key substrings"),
    network_indicators: Optional[str] = Query(None, description="Comma-separated list of network indicator substrings (IPs, domains, URLs)"),
    target_resources: Optional[str] = Query(None, description="Comma-separated list of extracted target resources (cloud resources, identity targets)"),
    source_tables: Optional[str] = Query(None, description="Comma-separated list of source tables (Sentinel KQL tables, Splunk indexes)"),
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
        mitre_groups=_parse_csv(mitre_groups),
        mitre_software=_parse_csv(mitre_software),
        tags=_parse_csv(tags),
        platforms=_parse_csv(platforms),
        event_categories=_parse_csv(event_categories),
        data_sources_normalized=_parse_csv(data_sources_normalized),
        use_cases=_parse_csv(use_cases),
        event_ids=_parse_csv(event_ids),
        process_names=_parse_csv(process_names),
        query_complexity=_parse_csv(query_complexity),
        api_actions=_parse_csv(api_actions),
        file_paths=_parse_csv(file_paths),
        registry_keys=_parse_csv(registry_keys),
        network_indicators=_parse_csv(network_indicators),
        target_resources=_parse_csv(target_resources),
        source_tables=_parse_csv(source_tables),
        offset=offset,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    search_service = SearchService(db)
    detections, total = await search_service.search_detections(filters)

    # Convert detections to list items with error handling
    items = []
    for d in detections:
        try:
            items.append(DetectionListItem.from_detection(d))
        except Exception as e:
            logger.error(f"Failed to serialize detection {d.id}: {e}")
            logger.error(f"Detection title: {d.title[:100] if d.title else 'None'}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to serialize detection {d.id}: {str(e)}"
            )

    return DetectionListResponse(
        items=items,
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
        mitre_groups=params.mitre_groups,
        mitre_software=params.mitre_software,
        tags=params.tags,
        platforms=params.platforms,
        event_categories=params.event_categories,
        data_sources_normalized=params.data_sources_normalized,
        use_cases=params.use_cases,
        event_ids=params.event_ids,
        process_names=params.process_names,
        query_complexity=params.query_complexity,
        api_actions=params.api_actions,
        file_paths=params.file_paths,
        registry_keys=params.registry_keys,
        network_indicators=params.network_indicators,
        target_resources=params.target_resources,
        source_tables=params.source_tables,
        offset=params.offset,
        limit=params.limit,
        sort_by=params.sort_by,
        sort_order=params.sort_order,
    )

    search_service = SearchService(db)
    detections, total = await search_service.search_detections(filters)

    return DetectionListResponse(
        items=[DetectionListItem.from_detection(d) for d in detections],
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
    """Get available filter options for dropdowns.

    Returns single-value facets (sources, statuses, severities,
    languages) plus the canonical taxonomy facets — platforms,
    data_sources, event_types — each as [{value, count}] sorted by
    descending count. Counts come directly from the corpus so the UI
    always reflects what's actually stored.
    """
    search_service = SearchService(db)

    return {
        "sources": await search_service.get_unique_values("source"),
        "statuses": await search_service.get_unique_values("status"),
        "severities": await search_service.get_unique_values("severity"),
        "languages": await search_service.get_unique_values("language"),
        # Canonical array facets powered by corpus counts. These are
        # what the FilterSidebar UI consumes.
        "platforms": await search_service.get_taxonomy_facet("platforms"),
        "data_sources": await search_service.get_taxonomy_facet("data_sources"),
        "event_types": await search_service.get_taxonomy_facet("event_types"),
        "use_cases": await search_service.get_taxonomy_facet("use_cases"),
        "mitre_groups": await search_service.get_taxonomy_facet("mitre_groups"),
        "mitre_software": await search_service.get_taxonomy_facet("mitre_software"),
    }


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single detection by ID."""
    search_service = SearchService(db)
    detection = await search_service.get_detection_by_id(detection_id)

    if not detection:
        raise HTTPException(status_code=404, detail=f"Detection not found: {detection_id}")

    return DetectionResponse.from_detection(detection)


def _parse_csv(value: Optional[str]) -> list[str]:
    """Parse a comma-separated string into a list."""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
