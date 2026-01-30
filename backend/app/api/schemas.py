"""Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# Detection schemas
class DetectionBase(BaseModel):
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
    log_sources: list[str] = []
    data_sources: list[str] = []
    # Standardized log source taxonomy
    platform: str = ""  # windows, linux, macos, cloud, network, email
    event_category: str = ""  # process, file, network, registry, authentication, etc.
    data_source_normalized: str = ""  # sysmon, auditd, cloudtrail, etc.
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    detection_logic: str
    language: str = "unknown"
    tags: list[str] = []
    references: list[str] = []
    false_positives: list[str] = []
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None


class DetectionResponse(DetectionBase):
    """Detection response with all fields."""

    raw_content: str
    created_at: datetime  # Sync timestamp
    updated_at: datetime  # Sync timestamp

    class Config:
        from_attributes = True


class DetectionListItem(BaseModel):
    """Detection item for list views (without detection_logic and raw_content for performance)."""

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
    log_sources: list[str] = []
    data_sources: list[str] = []
    # Standardized log source taxonomy
    platform: str = ""
    event_category: str = ""
    data_source_normalized: str = ""
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    # Truncated detection_logic for preview (first 500 chars)
    detection_logic_preview: str = ""
    language: str = "unknown"
    tags: list[str] = []
    references: list[str] = []
    false_positives: list[str] = []
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None
    created_at: datetime  # Sync timestamp
    updated_at: datetime  # Sync timestamp

    class Config:
        from_attributes = True

    @classmethod
    def from_detection(cls, detection) -> "DetectionListItem":
        """Create a list item from a detection, truncating detection_logic."""
        data = {
            "id": str(detection.id),
            "source": detection.source,
            "source_file": detection.source_file,
            "source_repo_url": detection.source_repo_url,
            "source_rule_url": detection.source_rule_url,
            "rule_id": detection.rule_id,
            "title": detection.title,
            "description": detection.description,
            "author": detection.author,
            "status": detection.status,
            "severity": detection.severity,
            "log_sources": detection.log_sources or [],
            "data_sources": detection.data_sources or [],
            "platform": detection.platform or "",
            "event_category": detection.event_category or "",
            "data_source_normalized": detection.data_source_normalized or "",
            "mitre_tactics": detection.mitre_tactics or [],
            "mitre_techniques": detection.mitre_techniques or [],
            "detection_logic_preview": (detection.detection_logic or "")[:500],
            "language": detection.language or "unknown",
            "tags": detection.tags or [],
            "references": detection.references or [],
            "false_positives": detection.false_positives or [],
            "rule_created_date": detection.rule_created_date,
            "rule_modified_date": detection.rule_modified_date,
            "created_at": detection.created_at,
            "updated_at": detection.updated_at,
        }
        return cls(**data)


class DetectionListResponse(BaseModel):
    """Paginated detection list response."""

    items: list[DetectionListItem]
    total: int
    offset: int
    limit: int


# Repository schemas
class RepositoryResponse(BaseModel):
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
    severities: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    # Standardized taxonomy filters
    platforms: list[str] = Field(default_factory=list)
    event_categories: list[str] = Field(default_factory=list)
    data_sources_normalized: list[str] = Field(default_factory=list)
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

    format: str = Field(default="json", pattern="^(json|csv)$")
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
