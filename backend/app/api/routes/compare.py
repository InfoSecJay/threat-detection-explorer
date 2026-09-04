"""Cross-vendor comparison API routes."""

from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.schemas import (
    CompareRequest, CompareResponse, DetectionListItem,
    SideBySideRequest, SideBySideResponse
)
from app.models.detection import Detection
from app.services.compare_diff import compute_observable_diff
from app.services.repository_sync import ALL_REPOSITORY_NAMES
from app.services.search import SearchService
from app.services.mitre import mitre_service
from app.services.corpus_cache import corpus_cache

router = APIRouter(prefix="/compare", tags=["compare"])


@router.get("/diff")
async def compare_observable_diff(
    ids: str = Query(..., description="2-6 comma-separated detection ids, in display order"),
    db: AsyncSession = Depends(get_db),
):
    """Observable-level diff of 2-6 rules (#11).

    One row per observable value (process name, registry key, API
    action...) and per metadata value (technique, data source...),
    with the rules it appears in, the rules where it is an exclusion,
    and the source field each rule tests it on. Powers the /compare
    page; GET so a comparison is a shareable URL.
    """
    id_list = list(dict.fromkeys(i.strip() for i in ids.split(",") if i.strip()))
    if len(id_list) < 2 or len(id_list) > 6:
        raise HTTPException(status_code=400, detail="Provide 2-6 detection ids")
    detections = await SearchService(db).get_detections_by_ids(id_list)
    by_id = {d.id: d for d in detections}
    ordered = [by_id[i] for i in id_list if i in by_id]
    if len(ordered) < 2:
        raise HTTPException(status_code=404, detail="At least 2 of the provided detection ids must exist")
    result = compute_observable_diff(ordered)
    result["missing_ids"] = [i for i in id_list if i not in by_id]
    return result


@router.get("")
async def compare_detections(
    technique: Optional[str] = Query(None, description="MITRE technique ID (e.g., T1059)"),
    keyword: Optional[str] = Query(None, description="Keyword to search in detection logic"),
    platform: Optional[str] = Query(None, description="Platform to filter by (e.g., windows, aws, okta)"),
    sources: Optional[str] = Query(None, description="Comma-separated list of sources to include"),
    db: AsyncSession = Depends(get_db),
):
    """Compare detections across vendors by technique, keyword, or platform.

    At least one of technique, keyword, or platform must be provided.
    """
    if not technique and not keyword and not platform:
        raise HTTPException(
            status_code=400,
            detail="One of 'technique', 'keyword', or 'platform' parameter is required",
        )

    search_service = SearchService(db)
    source_list = [s.strip() for s in sources.split(",")] if sources else None

    if technique:
        # Compare by MITRE technique
        grouped = await search_service.compare_by_technique(technique, source_list)
        query_type = "technique"
        query_value = technique
    elif platform:
        # Compare by platform
        grouped = await search_service.compare_by_platform(platform, source_list)
        query_type = "platform"
        query_value = platform
    else:
        # Compare by keyword
        grouped = await search_service.compare_by_keyword(keyword, source_list)
        query_type = "keyword"
        query_value = keyword

    # Convert to response format
    results = {}
    total_by_source = {}

    for source, detections in grouped.items():
        results[source] = [DetectionListItem.from_detection(d, verbose=True) for d in detections]
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
    if not request.technique and not request.keyword and not request.platform:
        raise HTTPException(
            status_code=400,
            detail="One of 'technique', 'keyword', or 'platform' is required",
        )

    search_service = SearchService(db)
    source_list = request.sources if request.sources else None

    if request.technique:
        grouped = await search_service.compare_by_technique(request.technique, source_list)
        query_type = "technique"
        query_value = request.technique
    elif request.platform:
        grouped = await search_service.compare_by_platform(request.platform, source_list)
        query_type = "platform"
        query_value = request.platform
    else:
        grouped = await search_service.compare_by_keyword(request.keyword, source_list)
        query_type = "keyword"
        query_value = request.keyword

    results = {}
    total_by_source = {}

    for source, detections in grouped.items():
        results[source] = [DetectionListItem.from_detection(d, verbose=True) for d in detections]
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
    if base_source not in ALL_REPOSITORY_NAMES:
        raise HTTPException(status_code=400, detail=f"Invalid base_source: {base_source}")
    if compare_source not in ALL_REPOSITORY_NAMES:
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
        "platforms": [", ".join(d.platforms) if d.platforms else "" for d in detections],
        "data_sources": [", ".join(d.data_sources) if d.data_sources else "" for d in detections],
        "event_types": [", ".join(d.event_types) if d.event_types else "" for d in detections],
        "mitre_tactics": [", ".join(d.mitre_tactics) if d.mitre_tactics else "" for d in detections],
        "mitre_techniques": [", ".join(d.mitre_techniques) if d.mitre_techniques else "" for d in detections],
        "description": [d.description or "" for d in detections],
        "detection_logic": [d.detection_logic or "" for d in detections],
    }

    return SideBySideResponse(
        detections=[DetectionListItem.from_detection(d, verbose=True) for d in detections],
        field_comparison=field_comparison,
    )


@router.get("/coverage-matrix")
async def get_coverage_matrix(
    tactic: Optional[str] = Query(None, description="Filter by tactic ID (e.g., TA0002)"),
    include_subtechniques: bool = Query(True, description="Include sub-techniques in the matrix"),
    domain: Optional[str] = Query(
        None,
        description="Restrict to rules of one attack-surface domain (#135): endpoint, identity, cloud, saas, network, email, devops, data, unknown",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Get MITRE technique coverage matrix across all sources.

    Returns coverage data showing which sources have detections for each technique,
    organized by tactic for matrix visualization. Corpus + catalog derived, so
    memoised on the corpus fingerprint (the Home hero and the ATT&CK browser
    both read it on every visit). `domain=` answers "what does the public
    rule set cover for identity / cloud / ..." over the rules of that domain.
    """
    from app.services.taxonomy.domains import is_canonical_domain

    if domain is not None and not is_canonical_domain(domain):
        raise HTTPException(status_code=400, detail=f"Unknown domain: {domain}")
    await mitre_service.ensure_loaded()
    key = ("mitre_coverage_matrix", tactic, include_subtechniques, domain, mitre_service.get_stats()["last_fetch"])
    return await corpus_cache.get(
        db, key, lambda: _compute_coverage_matrix(db, tactic, include_subtechniques, domain),
    )


async def coverage_rows(db: AsyncSession, domain: Optional[str] = None) -> list[tuple[str, list]]:
    """(source, mitre_techniques) for every rule, or for the rules of one
    domain. Split out so the domain filter is testable without ATT&CK data."""
    from sqlalchemy import String, cast

    query = select(Detection.source, Detection.mitre_techniques)
    if domain:
        query = query.where(cast(Detection.domains, String).ilike(f'%"{domain}"%'))
    return [(source, techniques) for source, techniques in (await db.execute(query)).all()]


async def _compute_coverage_matrix(
    db: AsyncSession, tactic: Optional[str], include_subtechniques: bool, domain: Optional[str] = None,
) -> dict:
    rows = await coverage_rows(db, domain)

    # Build coverage map: technique_id -> {source: count}
    coverage: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    sources_set: set[str] = set()
    unmapped_techniques: set[str] = set()

    for source, techniques in rows:
        if not techniques:
            continue
        sources_set.add(source)
        for tech_id in techniques:
            if not tech_id:
                continue

            # Map deprecated/revoked techniques to current equivalents
            mapped_id = mitre_service.map_technique(tech_id)
            if mapped_id:
                coverage[mapped_id][source] += 1
                # Also roll up sub-technique counts to parent technique
                if "." in mapped_id:
                    parent_id = mapped_id.split(".")[0]
                    coverage[parent_id][source] += 1
            else:
                # Track unmapped techniques for debugging
                unmapped_techniques.add(tech_id)

    sources = sorted(sources_set)

    # Get MITRE tactics and techniques
    all_tactics = mitre_service.get_all_tactics()
    all_techniques = mitre_service.get_all_techniques()

    # Filter techniques by tactic if specified
    if tactic:
        tactic = tactic.upper()
        if tactic not in all_tactics:
            raise HTTPException(status_code=400, detail=f"Invalid tactic ID: {tactic}")

    # Organize by tactic
    tactics_data = []

    # Kill-chain order from the ATT&CK matrix itself: a hardcoded list
    # dropped TA0112 (Defense Impairment, v18) and the 15 parent
    # techniques that live only there from the whole coverage browser.
    tactic_order = mitre_service.get_tactic_order()

    for tactic_id in tactic_order:
        if tactic and tactic_id != tactic:
            continue

        tactic_info = all_tactics.get(tactic_id)
        if not tactic_info or tactic_info.get("deprecated"):
            continue

        # Get techniques for this tactic
        tactic_techniques = []
        for tech_id, tech_info in all_techniques.items():
            # Skip deprecated or revoked techniques
            if tech_info.get("deprecated") or tech_info.get("revoked"):
                continue
            if tactic_id not in tech_info.get("tactics", []):
                continue
            if not include_subtechniques and tech_info.get("is_subtechnique"):
                continue

            # Get coverage for this technique
            tech_coverage = coverage.get(tech_id, {})
            total_count = sum(tech_coverage.values())

            tactic_techniques.append({
                "id": tech_id,
                "name": tech_info.get("name", ""),
                "is_subtechnique": tech_info.get("is_subtechnique", False),
                "coverage": {src: tech_coverage.get(src, 0) for src in sources},
                "total_detections": total_count,
                "sources_with_coverage": len([s for s in sources if tech_coverage.get(s, 0) > 0]),
            })

        # Sort techniques: parent techniques first, then subtechniques
        tactic_techniques.sort(key=lambda t: (t["is_subtechnique"], t["id"]))

        if tactic_techniques:  # Only include tactics with techniques
            tactics_data.append({
                "id": tactic_id,
                "name": tactic_info.get("name", ""),
                "short_name": tactic_info.get("short_name", ""),
                "techniques": tactic_techniques,
                "technique_count": len(tactic_techniques),
            })

    # ── Summary statistics ────────────────────────────────────────────
    # Stats must be computed over the UNIQUE set of techniques that
    # are actually in the tactic listings — NOT `coverage.keys()`
    # (which contains sub-technique → parent rollups that aren't in
    # any tactic's techniques[] list) and NOT sum-across-tactics
    # (which double-counts techniques tagged to multiple tactics).
    # A prior version produced stats like "Overall 223.2% coverage".
    unique_techniques: set[str] = set()
    unique_techniques_with_coverage: set[str] = set()
    unique_per_source: dict[str, set[str]] = {src: set() for src in sources}

    for t in tactics_data:
        for tech in t["techniques"]:
            tech_id = tech["id"]
            unique_techniques.add(tech_id)
            if tech["total_detections"] > 0:
                unique_techniques_with_coverage.add(tech_id)
            for src in sources:
                if tech["coverage"].get(src, 0) > 0:
                    unique_per_source[src].add(tech_id)

    total_unique = len(unique_techniques)
    covered_unique = len(unique_techniques_with_coverage)

    source_coverage = {
        src: {
            "covered_techniques": len(covered_set),
            "total_techniques": total_unique,
            "coverage_percent": round(
                (len(covered_set) / total_unique * 100) if total_unique else 0, 1
            ),
        }
        for src, covered_set in unique_per_source.items()
    }

    return {
        "sources": sources,
        "domain": domain,
        "tactics": tactics_data,
        "summary": {
            "total_tactics": len(tactics_data),
            "total_techniques": total_unique,
            "techniques_with_any_coverage": covered_unique,
            "overall_coverage_percent": round(
                (covered_unique / total_unique * 100) if total_unique else 0, 1
            ),
            "source_coverage": source_coverage,
            "unmapped_techniques": sorted(list(unmapped_techniques)) if unmapped_techniques else [],
        },
    }
