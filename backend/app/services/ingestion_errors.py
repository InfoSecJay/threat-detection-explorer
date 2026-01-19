"""Ingestion error tracking and reporting."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ErrorStage(str, Enum):
    """Stage where the error occurred."""
    DISCOVERY = "discovery"
    READ = "read"
    PARSE = "parse"
    NORMALIZE = "normalize"
    STORE = "store"


class ErrorSeverity(str, Enum):
    """Severity of the error."""
    WARNING = "warning"  # Rule skipped but not critical
    ERROR = "error"      # Rule failed processing


@dataclass
class IngestionError:
    """Represents a single error during ingestion."""

    file_path: str
    stage: ErrorStage
    severity: ErrorSeverity
    message: str
    details: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "stage": self.stage.value,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class IngestionStats:
    """Comprehensive statistics for an ingestion run."""

    # Counts
    discovered: int = 0
    skipped_by_filter: int = 0  # Files that didn't match can_parse()
    parsed: int = 0
    normalized: int = 0
    stored: int = 0

    # Error tracking
    errors: list[IngestionError] = field(default_factory=list)

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def add_error(
        self,
        file_path: str,
        stage: ErrorStage,
        message: str,
        details: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.ERROR
    ) -> None:
        """Add an error to the tracking list."""
        self.errors.append(IngestionError(
            file_path=str(file_path),  # Convert Path objects to string
            stage=stage,
            severity=severity,
            message=message,
            details=details,
        ))

    @property
    def error_count(self) -> int:
        """Total number of errors."""
        return len([e for e in self.errors if e.severity == ErrorSeverity.ERROR])

    @property
    def warning_count(self) -> int:
        """Total number of warnings."""
        return len([e for e in self.errors if e.severity == ErrorSeverity.WARNING])

    @property
    def success_rate(self) -> float:
        """Percentage of discovered rules successfully stored."""
        if self.discovered == 0:
            return 0.0
        return (self.stored / self.discovered) * 100

    @property
    def duration_seconds(self) -> Optional[float]:
        """Duration of ingestion in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def get_errors_by_stage(self) -> dict[str, list[dict]]:
        """Group errors by stage."""
        by_stage: dict[str, list[dict]] = {}
        for error in self.errors:
            stage = error.stage.value
            if stage not in by_stage:
                by_stage[stage] = []
            by_stage[stage].append(error.to_dict())
        return by_stage

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "discovered": self.discovered,
            "skipped_by_filter": self.skipped_by_filter,
            "parsed": self.parsed,
            "normalized": self.normalized,
            "stored": self.stored,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "success_rate": round(self.success_rate, 2),
            "duration_seconds": self.duration_seconds,
            "errors_by_stage": self.get_errors_by_stage(),
            # Include first N errors for quick review
            "sample_errors": [e.to_dict() for e in self.errors[:20]],
        }

    def to_summary_dict(self) -> dict:
        """Convert to summary dictionary (without error details)."""
        return {
            "discovered": self.discovered,
            "skipped_by_filter": self.skipped_by_filter,
            "parsed": self.parsed,
            "normalized": self.normalized,
            "stored": self.stored,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "success_rate": round(self.success_rate, 2),
            "duration_seconds": self.duration_seconds,
        }
