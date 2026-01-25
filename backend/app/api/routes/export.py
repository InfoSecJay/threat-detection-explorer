"""Export API routes."""

import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.schemas import ExportRequest, SearchParams
from app.services.search import SearchService, SearchFilters
from app.models.detection import Detection

router = APIRouter(prefix="/export", tags=["export"])


@router.post("")
async def export_detections(
    request: ExportRequest,
    db: AsyncSession = Depends(get_db),
):
    """Export detections in JSON or CSV format.

    Can export:
    - Specific IDs (if provided)
    - Filtered results (if filters provided)
    - All detections (if neither provided)
    """
    search_service = SearchService(db)

    # Get detections to export
    if request.ids:
        # Export specific IDs
        detections = []
        for detection_id in request.ids:
            detection = await search_service.get_detection_by_id(detection_id)
            if detection:
                detections.append(detection)
    else:
        # Export filtered or all detections
        if request.filters:
            filters = SearchFilters(
                search=request.filters.search,
                sources=request.filters.sources,
                statuses=request.filters.statuses,
                severities=request.filters.severities,
                languages=request.filters.languages,
                mitre_tactics=request.filters.mitre_tactics,
                mitre_techniques=request.filters.mitre_techniques,
                tags=request.filters.tags,
                log_sources=request.filters.log_sources,
                # Standardized taxonomy filters
                platforms=request.filters.platforms,
                event_categories=request.filters.event_categories,
                data_sources_normalized=request.filters.data_sources_normalized,
                offset=0,
                limit=100000,  # Large limit for export
            )
        else:
            filters = SearchFilters(offset=0, limit=100000)

        detections, _ = await search_service.search_detections(filters)

    if not detections:
        raise HTTPException(status_code=404, detail="No detections found to export")

    # Generate export
    if request.format == "json":
        return _export_json(detections, request.include_raw)
    else:
        return _export_csv(detections, request.include_raw)


def _export_json(detections: list[Detection], include_raw: bool) -> StreamingResponse:
    """Export detections as JSON."""
    data = []
    for d in detections:
        item = {
            "id": d.id,
            "source": d.source,
            "source_file": d.source_file,
            "source_repo_url": d.source_repo_url,
            "title": d.title,
            "description": d.description,
            "author": d.author,
            "status": d.status,
            "severity": d.severity,
            "log_sources": d.log_sources,
            "data_sources": d.data_sources,
            "mitre_tactics": d.mitre_tactics,
            "mitre_techniques": d.mitre_techniques,
            "detection_logic": d.detection_logic,
            "tags": d.tags,
            "created_at": d.created_at.isoformat(),
            "updated_at": d.updated_at.isoformat(),
        }
        if include_raw:
            item["raw_content"] = d.raw_content
        data.append(item)

    json_content = json.dumps(data, indent=2)

    return StreamingResponse(
        io.BytesIO(json_content.encode("utf-8")),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=detections_export.json"
        },
    )


def _export_csv(detections: list[Detection], include_raw: bool) -> StreamingResponse:
    """Export detections as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    headers = [
        "id",
        "source",
        "source_file",
        "source_repo_url",
        "title",
        "description",
        "author",
        "status",
        "severity",
        "log_sources",
        "data_sources",
        "mitre_tactics",
        "mitre_techniques",
        "detection_logic",
        "tags",
        "created_at",
        "updated_at",
    ]
    if include_raw:
        headers.append("raw_content")

    writer.writerow(headers)

    # Data rows
    for d in detections:
        row = [
            d.id,
            d.source,
            d.source_file,
            d.source_repo_url,
            d.title,
            d.description or "",
            d.author or "",
            d.status,
            d.severity,
            ",".join(d.log_sources),
            ",".join(d.data_sources),
            ",".join(d.mitre_tactics),
            ",".join(d.mitre_techniques),
            d.detection_logic,
            ",".join(d.tags),
            d.created_at.isoformat(),
            d.updated_at.isoformat(),
        ]
        if include_raw:
            row.append(d.raw_content)

        writer.writerow(row)

    csv_content = output.getvalue()

    return StreamingResponse(
        io.BytesIO(csv_content.encode("utf-8")),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=detections_export.csv"
        },
    )
