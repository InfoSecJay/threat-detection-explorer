"""Detection rule database model."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, Text, DateTime, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Detection(Base):
    """Normalized detection rule model."""

    __tablename__ = "detections"

    # Primary key - UUID for global uniqueness
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Source information
    source: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_file: Mapped[str] = mapped_column(String(500), nullable=False)
    source_repo_url: Mapped[str] = mapped_column(String(200), nullable=False)
    source_rule_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Rule identification
    rule_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)

    # Core metadata
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    author: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Status and severity
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
    )

    # Classification arrays (stored as JSON)
    log_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Standardized log source taxonomy
    platform: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
        index=True,
    )
    event_category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
        index=True,
    )
    data_source_normalized: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
        index=True,
    )

    # MITRE ATT&CK mapping
    mitre_tactics: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Detection logic - human-readable summary
    detection_logic: Mapped[str] = mapped_column(Text, nullable=False)

    # Rule language/format (e.g., sigma, eql, esql, spl, mql)
    language: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="unknown",
        index=True,
    )

    # Tags for classification
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # References (external links, CVEs, etc.)
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # False positives / known limitations
    false_positives: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Original rule content
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)

    # Rule dates (from source)
    rule_created_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rule_modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Timestamps (sync timestamps)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_detections_title", "title"),
        Index("ix_detections_source_file", "source_file"),
    )

    def __repr__(self) -> str:
        return f"<Detection(id={self.id}, source={self.source}, title={self.title[:50]})>"
