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


# Excel has a 32,767 character per cell limit; truncate to stay safe
_CSV_CELL_MAX = 32000


def _truncate(value: str | None, max_len: int = _CSV_CELL_MAX) -> str:
    """Truncate a string to max_len, appending a note if truncated."""
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "... [TRUNCATED]"


def _observables_cell(observables) -> str:
    """Flatten typed observables for a CSV cell:
    `process/process_name Image=powershell.exe|pwsh.exe; NOT network/port DestinationPort=443`."""
    parts = []
    for o in observables or []:
        if not isinstance(o, dict):
            continue
        values = "|".join(str(v) for v in (o.get("values") or []) if v is not None)
        prefix = "NOT " if o.get("negated") else ""
        parts.append(f"{prefix}{o.get('type')}/{o.get('subtype')} {o.get('field')}={values}")
    return "; ".join(parts)


def _safe_join(items: list | None, separator: str = "; ") -> str:
    """Safely join list items to a string, handling dicts and non-string types."""
    if not items:
        return ""
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            if "name" in item:
                result.append(str(item["name"]))
            elif "Schema" in item:
                result.append(item["Schema"])
            else:
                result.append(str(item))
        else:
            result.append(str(item))
    joined = separator.join(result)
    if len(joined) > _CSV_CELL_MAX:
        return joined[:_CSV_CELL_MAX] + "... [TRUNCATED]"
    return joined


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
                # Canonical taxonomy filters
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
            "source_rule_url": d.source_rule_url,
            "rule_id": d.rule_id,
            "title": d.title,
            "description": d.description,
            "author": d.author,
            "status": d.status,
            "is_building_block": bool(getattr(d, "is_building_block", False) or False),
            "severity": d.severity,
            "language": getattr(d, "language", "unknown") or "unknown",
            "platforms": getattr(d, "platforms", None) or [],
            "data_sources": getattr(d, "data_sources", None) or [],
            "event_types": getattr(d, "event_types", None) or [],
            "use_cases": getattr(d, "use_cases", None) or [],
            "mitre_tactics": d.mitre_tactics or [],
            "mitre_techniques": d.mitre_techniques or [],
            "mitre_groups": getattr(d, "mitre_groups", None) or [],
            "mitre_software": getattr(d, "mitre_software", None) or [],
            "detection_logic": d.detection_logic,
            "tags": d.tags or [],
            "references": d.references or [],
            "false_positives": d.false_positives or [],
            "extracted_fields_used": getattr(d, "extracted_fields_used", None) or [],
            "extracted_event_ids": getattr(d, "extracted_event_ids", None) or [],
            "extracted_process_names": getattr(d, "extracted_process_names", None) or [],
            "extracted_file_paths": getattr(d, "extracted_file_paths", None) or [],
            "extracted_registry_keys": getattr(d, "extracted_registry_keys", None) or [],
            "extracted_network_indicators": getattr(d, "extracted_network_indicators", None) or [],
            "extracted_source_tables": getattr(d, "extracted_source_tables", None) or [],
            "query_complexity": getattr(d, "query_complexity", "unknown") or "unknown",
            "extracted_api_actions": getattr(d, "extracted_api_actions", None) or [],
            "extracted_target_resources": getattr(d, "extracted_target_resources", None) or [],
            # Typed observables (type/subtype/field/values/negated) —
            # the structured form behind the flat extracted_* surfaces.
            "extracted_observables": getattr(d, "extracted_observables", None) or [],
            "rule_created_date": d.rule_created_date.isoformat() if d.rule_created_date else None,
            "rule_modified_date": d.rule_modified_date.isoformat() if d.rule_modified_date else None,
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
        "source_rule_url",
        "rule_id",
        "title",
        "description",
        "author",
        "status",
        "is_building_block",
        "severity",
        "language",
        "platforms",
        "data_sources",
        "event_types",
        "use_cases",
        "mitre_tactics",
        "mitre_techniques",
        "mitre_groups",
        "mitre_software",
        "detection_logic",
        "tags",
        "references",
        "false_positives",
        "extracted_fields_used",
        "extracted_event_ids",
        "extracted_process_names",
        "extracted_file_paths",
        "extracted_registry_keys",
        "extracted_network_indicators",
        "extracted_source_tables",
        "query_complexity",
        "extracted_api_actions",
        "extracted_target_resources",
        "extracted_observables",
        "rule_created_date",
        "rule_modified_date",
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
            d.source_rule_url or "",
            d.rule_id or "",
            d.title,
            d.description or "",
            d.author or "",
            d.status,
            "true" if getattr(d, "is_building_block", False) else "false",
            d.severity,
            getattr(d, "language", "unknown") or "unknown",
            _safe_join(getattr(d, "platforms", None)),
            _safe_join(getattr(d, "data_sources", None)),
            _safe_join(getattr(d, "event_types", None)),
            _safe_join(getattr(d, "use_cases", None)),
            _safe_join(d.mitre_tactics),
            _safe_join(d.mitre_techniques),
            _safe_join(getattr(d, "mitre_groups", None)),
            _safe_join(getattr(d, "mitre_software", None)),
            _truncate(d.detection_logic),
            _safe_join(d.tags),
            _safe_join(d.references),
            _safe_join(d.false_positives),
            _safe_join(getattr(d, "extracted_fields_used", None)),
            _safe_join(getattr(d, "extracted_event_ids", None)),
            _safe_join(getattr(d, "extracted_process_names", None)),
            _safe_join(getattr(d, "extracted_file_paths", None)),
            _safe_join(getattr(d, "extracted_registry_keys", None)),
            _safe_join(getattr(d, "extracted_network_indicators", None)),
            _safe_join(getattr(d, "extracted_source_tables", None)),
            getattr(d, "query_complexity", "unknown") or "unknown",
            _safe_join(getattr(d, "extracted_api_actions", None)),
            _safe_join(getattr(d, "extracted_target_resources", None)),
            _observables_cell(getattr(d, "extracted_observables", None)),
            d.rule_created_date.isoformat() if d.rule_created_date else "",
            d.rule_modified_date.isoformat() if d.rule_modified_date else "",
            d.created_at.isoformat(),
            d.updated_at.isoformat(),
        ]
        if include_raw:
            row.append(_truncate(d.raw_content))

        writer.writerow(row)

    csv_content = output.getvalue()

    return StreamingResponse(
        io.BytesIO(csv_content.encode("utf-8")),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=detections_export.csv"
        },
    )
