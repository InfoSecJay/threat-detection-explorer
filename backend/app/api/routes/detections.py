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


@router.get("", response_model=DetectionListResponse, response_model_exclude_none=True)
async def list_detections(
    verbose: bool = Query(
        False,
        description=(
            "false (default): slim rows -- the catalog table's columns only. "
            "true: full rows including detection_logic, references, "
            "false_positives and the extracted_* observable arrays."
        ),
    ),
    search: Optional[str] = None,
    q: Optional[str] = Query(
        None,
        description=(
            "Lucene-syntax query. Examples: `actor:APT29 AND severity:high`, "
            "`title:\"cobalt strike\"`, `tech:T1059 NOT platform:linux`. See "
            "/query for the full field reference. Malformed queries return 400."
        ),
    ),
    sources: Optional[str] = Query(None, description="Comma-separated list of sources"),
    statuses: Optional[str] = Query(None, description="Comma-separated list of statuses"),
    building_block: Optional[bool] = Query(None, description="true = building-block / signal-only rules only, false = hide them, omit = both"),
    min_quality: Optional[int] = Query(None, ge=0, le=100, description="Minimum hygiene score (0-100), inclusive; unscored rules never match"),
    severities: Optional[str] = Query(None, description="Comma-separated list of severities"),
    languages: Optional[str] = Query(None, description="Comma-separated list of rule languages"),
    rule_modalities: Optional[str] = Query(None, description="Comma-separated rule modalities: rule, hunting, ml_job, correlation, indicator_match, building_block"),
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
    sort_by: str = Query("rule_created_date"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """List detections with filtering and pagination."""
    # Parse comma-separated values
    filters = SearchFilters(
        search=search,
        q=q,
        sources=_parse_csv(sources),
        statuses=_parse_csv(statuses),
        building_block=building_block,
        min_quality=min_quality,
        severities=_parse_csv(severities),
        languages=_parse_csv(languages),
        rule_modalities=_parse_csv(rule_modalities),
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
    try:
        detections, total = await search_service.search_detections(filters)
    except Exception as e:
        # Surface query-parse errors as 400s so the FE can inline them.
        from app.services.query_parser import QueryParseError
        if isinstance(e, QueryParseError):
            raise HTTPException(status_code=400, detail={
                "error": "query_parse_error",
                "message": e.message,
                "position": e.position,
                "suggestion": e.suggestion,
            })
        raise

    # Convert detections to list items with error handling
    items = []
    for d in detections:
        try:
            items.append(DetectionListItem.from_detection(d, verbose=verbose))
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
        building_block=params.building_block,
        min_quality=params.min_quality,
        severities=params.severities,
        languages=params.languages,
        rule_modalities=params.rule_modalities,
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
        items=[DetectionListItem.from_detection(d, verbose=True) for d in detections],
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
    return await SearchService(db).get_filter_options()


@router.get("/facets")
async def get_facets(
    search: Optional[str] = None,
    q: Optional[str] = Query(None, description="Lucene-syntax query (same as /detections)"),
    sources: Optional[str] = Query(None),
    statuses: Optional[str] = Query(None),
    building_block: Optional[bool] = Query(None),
    min_quality: Optional[int] = Query(None, ge=0, le=100, description="Minimum hygiene score (0-100), inclusive; unscored rules never match"),
    severities: Optional[str] = Query(None),
    languages: Optional[str] = Query(None),
    rule_modalities: Optional[str] = Query(None),
    mitre_tactics: Optional[str] = Query(None),
    mitre_techniques: Optional[str] = Query(None),
    mitre_groups: Optional[str] = Query(None),
    mitre_software: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    platforms: Optional[str] = Query(None),
    event_categories: Optional[str] = Query(None),
    data_sources_normalized: Optional[str] = Query(None),
    use_cases: Optional[str] = Query(None),
    event_ids: Optional[str] = Query(None),
    process_names: Optional[str] = Query(None),
    query_complexity: Optional[str] = Query(None),
    api_actions: Optional[str] = Query(None),
    file_paths: Optional[str] = Query(None),
    registry_keys: Optional[str] = Query(None),
    network_indicators: Optional[str] = Query(None),
    target_resources: Optional[str] = Query(None),
    source_tables: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Faceted counts for the filter sidebar, scoped to the active query.

    Accepts the same filter params as GET /detections (minus pagination
    and sorting) and returns per-dimension [{value, count}] lists.
    Counts narrow as filters apply; each dimension excludes its own
    selection so sibling options within a dimension stay visible.
    """
    filters = SearchFilters(
        search=search,
        q=q,
        sources=_parse_csv(sources),
        statuses=_parse_csv(statuses),
        building_block=building_block,
        min_quality=min_quality,
        severities=_parse_csv(severities),
        languages=_parse_csv(languages),
        rule_modalities=_parse_csv(rule_modalities),
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
    )

    search_service = SearchService(db)
    try:
        return await search_service.get_facets(filters)
    except Exception as e:
        from app.services.query_parser import QueryParseError
        if isinstance(e, QueryParseError):
            raise HTTPException(status_code=400, detail={
                "error": "query_parse_error",
                "message": e.message,
                "position": e.position,
                "suggestion": e.suggestion,
            })
        raise


@router.get("/{detection_id}/related")
async def get_related_detections(
    detection_id: str,
    limit: int = Query(12, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Rules that key on the same things -- technique plus shared
    process names, registry keys, API actions, paths, indicators, event
    IDs -- ranked by overlap, other vendors first at equal score."""
    from app.services.related import related_for_id
    out = await related_for_id(db, detection_id, limit)
    if out is None:
        raise HTTPException(status_code=404, detail=f"Detection not found: {detection_id}")
    return out


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single detection by canonical id, legacy id, or upstream
    rule id. Alias matches 301 to the canonical URL (#86)."""
    from fastapi.responses import RedirectResponse

    from app.services.detection_resolver import resolve_detection

    detection, via_alias = await resolve_detection(db, detection_id)
    if detection is None:
        # Tombstone (#87): a rule removed upstream answers 410 Gone
        # with its history and live successors, never a bare 404.
        from fastapi.responses import JSONResponse

        from app.services.tombstones import get_tombstone

        tomb = await get_tombstone(db, detection_id)
        if tomb is not None:
            return JSONResponse(status_code=410, content=tomb)
        raise HTTPException(status_code=404, detail=f"Detection not found: {detection_id}")
    if via_alias:
        from app.config import settings

        return RedirectResponse(
            url=f"{settings.api_prefix}{router.prefix}/{detection.id}", status_code=301,
        )
    return DetectionResponse.from_detection(detection)


def _parse_csv(value: Optional[str]) -> list[str]:
    """Parse a comma-separated string into a list."""
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
