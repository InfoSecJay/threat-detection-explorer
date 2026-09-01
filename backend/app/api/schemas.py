"""Pydantic schemas for API request/response models."""

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_serializer

from app.utils.datetime_utils import to_utc_iso


class UtcTimestampsModel(BaseModel):
    """Base for response models carrying stored (naive UTC) datetimes.

    Serializes every datetime field with a trailing ``Z`` (#52) so API
    consumers -- browsers included -- parse them as UTC instead of local
    time. Column storage stays naive; only the wire format changes.
    """

    @field_serializer("*", mode="wrap")
    def _serialize_utc(self, value, handler, info):
        if isinstance(value, datetime):
            return to_utc_iso(value)
        return handler(value)


def sanitize_string(value: str | None) -> str:
    """Sanitize a string for JSON serialization.

    Removes null bytes, control characters, and invalid Unicode that
    can cause JSON serialization to fail.
    """
    if value is None:
        return ""
    try:
        # If value is bytes, decode it
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        # Convert to string if needed
        value = str(value)
        # Remove null bytes and other problematic control characters
        # Keep common whitespace (tab, newline, carriage return)
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        # Remove surrogate pairs that cause JSON encoding issues
        sanitized = sanitized.encode('utf-8', errors='surrogateescape').decode('utf-8', errors='replace')
        return sanitized
    except Exception:
        # If all else fails, return an empty string
        return ""


def normalize_string_list(items: list | None) -> list[str]:
    """Normalize a list to contain only strings.

    Handles cases where list items might be dicts or other types
    that need to be converted to strings.
    """
    if not items:
        return []
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            # Convert dict to a meaningful string representation
            # Try common dict patterns first
            if "name" in item:
                result.append(str(item["name"]))
            elif "id" in item:
                result.append(str(item["id"]))
            elif "Schema" in item:
                # Sentinel schema tags - extract the schema name
                result.append(item.get("Schema", str(item)))
            else:
                # Fall back to string representation
                result.append(str(item))
        else:
            result.append(str(item))
    return result


# Detection schemas
def _int_or_none(value):
    """Coerce to int or None — legacy rows carry junk in quality columns."""
    return value if isinstance(value, int) else None


def _dict_or_none(value):
    """Coerce to dict or None — pre-#10 ingests stored `[]` here."""
    return value if isinstance(value, dict) else None


class DetectionBase(UtcTimestampsModel):
    """Base detection schema with common fields."""

    id: str
    source: str
    source_file: str
    source_repo_url: str
    source_rule_url: Optional[str] = None
    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    author: Optional[str] = None
    status: str
    severity: str
    # Building-block / signal-only rule (issue #26). Legacy rows may be
    # NULL until the next sync; builders coerce to False.
    is_building_block: bool = False
    # Canonical taxonomy (Phase 3 final names). See docs/taxonomy.md.
    platforms: list[str] = []
    data_sources: list[str] = []
    event_types: list[str] = []
    # Vendor-preserved analytic story / use-case labels. Populated for
    # Splunk (analytic_story), Elastic (Use Case: tags), Sublime
    # (attack_types); empty on sources without a native concept.
    use_cases: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    # Raw ATT&CK Group + Software IDs; FE resolves display names.
    mitre_groups: list[str] = []
    mitre_software: list[str] = []
    detection_logic: str
    language: str = "unknown"
    tags: list[str] = []
    references: list[str] = []
    false_positives: list[str] = []
    # Vendor-authored investigation guide (markdown), when present.
    investigation_guide: Optional[str] = None
    # Extracted observable fields
    extracted_fields_used: list[str] = []
    extracted_event_ids: list[str] = []
    extracted_process_names: list[str] = []
    extracted_file_paths: list[str] = []
    extracted_registry_keys: list[str] = []
    extracted_network_indicators: list[str] = []
    extracted_source_tables: list[str] = []
    extracted_observables: list[dict] = []
    query_complexity: str = "unknown"
    extracted_api_actions: list[str] = []
    extracted_target_resources: list[str] = []
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None
    # Deterministic hygiene score (issue #10) — rule hygiene, NOT
    # detection efficacy. Null until the row is (re)scored by ingest.
    quality_score: Optional[int] = None
    quality_details: Optional[dict] = None


class DetectionResponse(DetectionBase):
    """Detection response with all fields."""

    raw_content: str
    created_at: datetime  # Sync timestamp
    updated_at: datetime  # Sync timestamp

    class Config:
        from_attributes = True

    @classmethod
    def from_detection(cls, detection) -> "DetectionResponse":
        """Create a response from a detection ORM object with safe serialization."""
        data = {
            "id": str(detection.id),
            "source": detection.source,
            "source_file": sanitize_string(detection.source_file),
            "source_repo_url": sanitize_string(detection.source_repo_url),
            "source_rule_url": sanitize_string(detection.source_rule_url),
            "rule_id": sanitize_string(detection.rule_id),
            "title": sanitize_string(detection.title),
            "description": sanitize_string(detection.description),
            "author": sanitize_string(detection.author),
            "status": detection.status,
            "severity": detection.severity,
            "is_building_block": bool(getattr(detection, "is_building_block", False) or False),
            # Canonical taxonomy (Phase 3 final names)
            "platforms": getattr(detection, 'platforms', None) or [],
            "data_sources": getattr(detection, 'data_sources', None) or [],
            "event_types": getattr(detection, 'event_types', None) or [],
            "use_cases": getattr(detection, 'use_cases', None) or [],
            "mitre_tactics": normalize_string_list(detection.mitre_tactics),
            "mitre_techniques": normalize_string_list(detection.mitre_techniques),
            "mitre_groups": getattr(detection, 'mitre_groups', None) or [],
            "mitre_software": getattr(detection, 'mitre_software', None) or [],
            "detection_logic": sanitize_string(detection.detection_logic) or "",
            "language": detection.language or "unknown",
            "tags": normalize_string_list(detection.tags),
            "references": normalize_string_list(detection.references),
            "false_positives": normalize_string_list(detection.false_positives),
            "investigation_guide": getattr(detection, "investigation_guide", None) or None,
            "extracted_fields_used": getattr(detection, 'extracted_fields_used', None) or [],
            "extracted_event_ids": getattr(detection, 'extracted_event_ids', None) or [],
            "extracted_process_names": getattr(detection, 'extracted_process_names', None) or [],
            "extracted_file_paths": getattr(detection, 'extracted_file_paths', None) or [],
            "extracted_registry_keys": getattr(detection, 'extracted_registry_keys', None) or [],
            "extracted_network_indicators": getattr(detection, 'extracted_network_indicators', None) or [],
            "extracted_source_tables": getattr(detection, 'extracted_source_tables', None) or [],
            "extracted_observables": getattr(detection, 'extracted_observables', None) or [],
            "query_complexity": getattr(detection, 'query_complexity', None) or "unknown",
            "extracted_api_actions": getattr(detection, 'extracted_api_actions', None) or [],
            "extracted_target_resources": getattr(detection, 'extracted_target_resources', None) or [],
            "rule_created_date": detection.rule_created_date,
            "rule_modified_date": detection.rule_modified_date,
            # Legacy rows (pre-#10 ingests) carry `[]` in quality_details
            # — coerce anything non-dict to None so serialization never
            # 500s on old data awaiting its rescore.
            "quality_score": _int_or_none(getattr(detection, 'quality_score', None)),
            "quality_details": _dict_or_none(getattr(detection, 'quality_details', None)),
            "raw_content": sanitize_string(detection.raw_content) or "",
            "created_at": detection.created_at,
            "updated_at": detection.updated_at,
        }
        return cls(**data)


class DetectionListItem(UtcTimestampsModel):
    """Detection item for list views (without raw_content)."""

    id: str
    source: str
    source_file: str
    source_repo_url: str
    source_rule_url: Optional[str] = None
    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    author: Optional[str] = None
    status: str
    severity: str
    # Building-block / signal-only rule (issue #26). Legacy rows may be
    # NULL until the next sync; builders coerce to False.
    is_building_block: bool = False
    # Canonical taxonomy (Phase 3 final names). See docs/taxonomy.md.
    platforms: list[str] = []
    data_sources: list[str] = []
    event_types: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    # Raw ATT&CK Group + Software IDs; FE resolves display names.
    mitre_groups: list[str] = []
    mitre_software: list[str] = []
    language: str = "unknown"
    # Heavy fields below are None unless ?verbose=true (teardown R15 /
    # #113): the default list response was 149 KB for 25 rows with ~85%
    # of the payload never rendered by the table. None (not []) so
    # response_model_exclude_none drops the keys from the slim response.
    detection_logic: Optional[str] = None
    use_cases: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    references: Optional[list[str]] = None
    false_positives: Optional[list[str]] = None
    extracted_fields_used: Optional[list[str]] = None
    extracted_event_ids: Optional[list[str]] = None
    extracted_process_names: Optional[list[str]] = None
    extracted_file_paths: Optional[list[str]] = None
    extracted_registry_keys: Optional[list[str]] = None
    extracted_network_indicators: Optional[list[str]] = None
    extracted_source_tables: Optional[list[str]] = None
    extracted_observables: Optional[list[dict]] = None
    query_complexity: Optional[str] = None
    extracted_api_actions: Optional[list[str]] = None
    extracted_target_resources: Optional[list[str]] = None
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None
    quality_score: Optional[int] = None
    created_at: datetime  # Sync timestamp
    updated_at: datetime  # Sync timestamp

    class Config:
        from_attributes = True

    @classmethod
    def from_detection(cls, detection, verbose: bool = False) -> "DetectionListItem":
        """Create a list item from a detection.

        Sanitizes string fields to handle control characters that could
        cause JSON serialization failures. Slim by default (teardown
        R15 / #113); verbose restores the full row for API consumers.
        """
        data = {
            "id": str(detection.id),
            "source": detection.source,
            "source_file": sanitize_string(detection.source_file),
            "source_repo_url": sanitize_string(detection.source_repo_url),
            "source_rule_url": sanitize_string(detection.source_rule_url),
            "rule_id": sanitize_string(detection.rule_id),
            "title": sanitize_string(detection.title),
            "description": sanitize_string(detection.description),
            "author": sanitize_string(detection.author),
            "status": detection.status,
            "severity": detection.severity,
            "is_building_block": bool(getattr(detection, "is_building_block", False) or False),
            # Canonical taxonomy (Phase 3 final names)
            "platforms": getattr(detection, 'platforms', None) or [],
            "data_sources": getattr(detection, 'data_sources', None) or [],
            "event_types": getattr(detection, 'event_types', None) or [],
            "mitre_tactics": normalize_string_list(detection.mitre_tactics),
            "mitre_techniques": normalize_string_list(detection.mitre_techniques),
            "mitre_groups": getattr(detection, 'mitre_groups', None) or [],
            "mitre_software": getattr(detection, 'mitre_software', None) or [],
            "language": detection.language or "unknown",
            "rule_created_date": detection.rule_created_date,
            "rule_modified_date": detection.rule_modified_date,
            "quality_score": _int_or_none(getattr(detection, 'quality_score', None)),
            "created_at": detection.created_at,
            "updated_at": detection.updated_at,
        }
        if verbose:
            data.update({
                "detection_logic": sanitize_string(detection.detection_logic) or "",
                "use_cases": getattr(detection, 'use_cases', None) or [],
                "tags": normalize_string_list(detection.tags),
                "references": normalize_string_list(detection.references),
                "false_positives": normalize_string_list(detection.false_positives),
                "extracted_fields_used": getattr(detection, 'extracted_fields_used', None) or [],
                "extracted_event_ids": getattr(detection, 'extracted_event_ids', None) or [],
                "extracted_process_names": getattr(detection, 'extracted_process_names', None) or [],
                "extracted_file_paths": getattr(detection, 'extracted_file_paths', None) or [],
                "extracted_registry_keys": getattr(detection, 'extracted_registry_keys', None) or [],
                "extracted_network_indicators": getattr(detection, 'extracted_network_indicators', None) or [],
                "extracted_source_tables": getattr(detection, 'extracted_source_tables', None) or [],
                "extracted_observables": getattr(detection, 'extracted_observables', None) or [],
                "query_complexity": getattr(detection, 'query_complexity', None) or "unknown",
                "extracted_api_actions": getattr(detection, 'extracted_api_actions', None) or [],
                "extracted_target_resources": getattr(detection, 'extracted_target_resources', None) or [],
            })
        return cls(**data)


class DetectionListResponse(BaseModel):
    """Paginated detection list response."""

    items: list[DetectionListItem]
    total: int
    offset: int
    limit: int


# Repository schemas
class RepositoryResponse(UtcTimestampsModel):
    """Repository metadata response."""

    id: str
    name: str
    url: str
    last_commit_hash: Optional[str] = None
    last_sync_at: Optional[datetime] = None
    rule_count: int
    status: str
    error_message: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class SyncResponse(BaseModel):
    """Sync operation response."""

    success: bool
    message: str
    repository: Optional[str] = None


class IngestionErrorSchema(BaseModel):
    """Single ingestion error details."""

    file_path: str
    stage: str
    severity: str
    message: str
    details: Optional[str] = None
    timestamp: str


class IngestionStatsSchema(BaseModel):
    """Comprehensive ingestion statistics."""

    discovered: int
    skipped_by_filter: int
    parsed: int
    normalized: int
    stored: int
    error_count: int
    warning_count: int
    success_rate: float
    duration_seconds: Optional[float] = None
    errors_by_stage: dict[str, list[IngestionErrorSchema]] = Field(default_factory=dict)
    sample_errors: list[IngestionErrorSchema] = Field(default_factory=list)


class IngestionSummarySchema(BaseModel):
    """Summary-only ingestion statistics (without error details)."""

    discovered: int
    skipped_by_filter: int
    parsed: int
    normalized: int
    stored: int
    error_count: int
    warning_count: int
    success_rate: float
    duration_seconds: Optional[float] = None


class IngestionResponse(BaseModel):
    """Ingestion operation response."""

    success: bool
    message: str
    stats: IngestionStatsSchema


# Search schemas
class SearchParams(BaseModel):
    """Search parameters for filtering detections."""

    search: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    # True = building blocks only, False = hide them, None = both.
    building_block: Optional[bool] = None
    # Minimum hygiene score, inclusive (#39).
    min_quality: Optional[int] = Field(default=None, ge=0, le=100)
    severities: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)
    mitre_software: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    # Canonical taxonomy filters (Phase 3 final names; the
    # `event_categories` / `data_sources_normalized` keys are kept
    # for URL backwards-compat with the FilterPanel UI but match
    # the renamed `event_types` / `data_sources` columns).
    platforms: list[str] = Field(default_factory=list)
    event_categories: list[str] = Field(default_factory=list)
    data_sources_normalized: list[str] = Field(default_factory=list)
    # Analytic story / vendor use-case labels
    use_cases: list[str] = Field(default_factory=list)
    # Extracted observable filters
    event_ids: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    query_complexity: list[str] = Field(default_factory=list)
    api_actions: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)
    network_indicators: list[str] = Field(default_factory=list)
    target_resources: list[str] = Field(default_factory=list)
    source_tables: list[str] = Field(default_factory=list)
    offset: int = 0
    limit: int = Field(default=50, le=200)
    sort_by: str = "title"
    sort_order: str = "asc"


# Compare schemas
class CompareRequest(BaseModel):
    """Request for comparison queries."""

    technique: Optional[str] = None
    keyword: Optional[str] = None
    platform: Optional[str] = None
    sources: list[str] = Field(default_factory=list)


class CompareResponse(BaseModel):
    """Comparison response with grouped detections."""

    query_type: str  # "technique", "keyword", or "platform"
    query_value: str
    results: dict[str, list[DetectionListItem]]
    total_by_source: dict[str, int]


# Side-by-side comparison schemas
class SideBySideRequest(BaseModel):
    """Request for side-by-side rule comparison."""

    ids: list[str] = Field(..., min_length=2, max_length=6)


class SideBySideResponse(BaseModel):
    """Side-by-side comparison response."""

    detections: list[DetectionListItem]
    field_comparison: dict[str, list[Optional[str]]]  # field -> values per detection


# Export schemas
class ExportRequest(BaseModel):
    """Export request with filters and format."""

    format: str = Field(default="json", pattern="^(json|csv|navigator|observables)$")
    filters: Optional[SearchParams] = None
    ids: list[str] = Field(default_factory=list)
    include_raw: bool = False


# Statistics schemas
class StatisticsResponse(BaseModel):
    """Statistics response."""

    total: int
    by_source: dict[str, int]
    by_severity: dict[str, int]
    by_status: dict[str, int]
    # Hygiene averages over scored rows (#39). Optional so an older
    # service response shape still validates.
    quality_avg: Optional[float] = None
    quality_by_source: dict[str, dict[str, float]] = Field(default_factory=dict)
