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

    # Taxonomy coverage signals (Issue 2 observability layer). Populated
    # from `NormalizedDetection.taxonomy_matched` + `taxonomy_fingerprint`
    # during ingestion. Feeds per-sync coverage metrics + drift
    # notifications — never surfaced to the public frontend.
    taxonomy_matched_count: int = 0
    taxonomy_unmatched_count: int = 0
    # Aggregated unmapped rules grouped by logsource fingerprint, so
    # "50 new rules with product=foo/service=bar" collapses to one row.
    # Shape: {fingerprint: {"count": int, "samples": [rule_summary, ...]}}
    # where each sample is {"rule_id", "source_file", "title"}. Sample
    # list is capped at 5 per fingerprint to keep the payload small.
    taxonomy_unmatched_by_fingerprint: dict[str, dict] = field(default_factory=dict)

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

    def record_taxonomy_result(
        self,
        matched: bool,
        fingerprint: str,
        rule_id: Optional[str],
        source_file: str,
        title: str,
    ) -> None:
        """Track taxonomy resolver outcome for one rule.

        `matched=True` means the vendor resolver produced at least one
        canonical value. `matched=False` means the logsource signature
        fell through to UNKNOWN — we group these by fingerprint so
        identical misses coalesce into one drift-report row.
        """
        if matched:
            self.taxonomy_matched_count += 1
            return

        self.taxonomy_unmatched_count += 1
        bucket = self.taxonomy_unmatched_by_fingerprint.setdefault(
            fingerprint or "-",
            {"count": 0, "samples": []},
        )
        bucket["count"] += 1
        # Cap samples per fingerprint so JSON stays small even with huge
        # corpora. The first 5 are plenty to eyeball the pattern.
        if len(bucket["samples"]) < 5:
            bucket["samples"].append({
                "rule_id": rule_id,
                "source_file": source_file,
                "title": title,
            })

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

    @property
    def taxonomy_coverage_percent(self) -> float:
        """Percentage of normalized rules that resolved to a canonical mapping."""
        total = self.taxonomy_matched_count + self.taxonomy_unmatched_count
        if total == 0:
            return 0.0
        return (self.taxonomy_matched_count / total) * 100

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
            "taxonomy_matched": self.taxonomy_matched_count,
            "taxonomy_unmatched": self.taxonomy_unmatched_count,
            "taxonomy_coverage_percent": round(self.taxonomy_coverage_percent, 2),
            "taxonomy_unmatched_by_fingerprint": self.taxonomy_unmatched_by_fingerprint,
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
            "taxonomy_matched": self.taxonomy_matched_count,
            "taxonomy_unmatched": self.taxonomy_unmatched_count,
            "taxonomy_coverage_percent": round(self.taxonomy_coverage_percent, 2),
        }
