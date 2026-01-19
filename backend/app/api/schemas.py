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
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    detection_logic: str
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


class DetectionListItem(DetectionBase):
    """Detection item for list views (without raw_content)."""

    created_at: datetime  # Sync timestamp
    updated_at: datetime  # Sync timestamp

    class Config:
        from_attributes = True


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
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    offset: int = 0
    limit: int = Field(default=50, le=200)
    sort_by: str = "title"
    sort_order: str = "asc"


# Compare schemas
class CompareRequest(BaseModel):
    """Request for comparison queries."""

    technique: Optional[str] = None
    keyword: Optional[str] = None
    sources: list[str] = Field(default_factory=list)


class CompareResponse(BaseModel):
    """Comparison response with grouped detections."""

    query_type: str  # "technique" or "keyword"
    query_value: str
    results: dict[str, list[DetectionListItem]]
    total_by_source: dict[str, int]


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
