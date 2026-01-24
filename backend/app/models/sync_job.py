"""Sync job tracking database model."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, DateTime, Integer, Text, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SyncJob(Base):
    """Track sync and ingestion job history."""

    __tablename__ = "sync_jobs"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Job identification
    job_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )  # "sync", "ingest", or "full" (sync + ingest)

    repository: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )  # None if all repositories

    # Trigger info
    triggered_by: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="manual",
    )  # "manual", "scheduled", "webhook"

    # Status
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
    )  # "pending", "running", "completed", "failed"

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Results
    rules_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rules_stored: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Detailed results per repository (for "all" jobs)
    repository_results: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Error information
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    def __repr__(self) -> str:
        return f"<SyncJob(id={self.id[:8]}, type={self.job_type}, status={self.status})>"
