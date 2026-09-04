"""Detection rule database model."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, Text, DateTime, JSON, Integer, Index, Boolean, false
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow


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

    # Rule identification. Free-form: format varies per source (UUID for
    # Sigma/Elastic/Auth0, dotted human-readable name for Panther, event
    # name for Okta/Google SecOps). 200 chars covers Panther's longest
    # dotted paths (e.g. `Microsoft365.Audit.AzureActiveDirectory...`)
    # with margin.
    rule_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)

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
    # Building-block / signal-only rule (issue #26): emits signal for
    # other rules to correlate on instead of alerting by itself
    # (Elastic `building_block_type` / `rules_building_block/`, Panther
    # `CreateAlert: false` / `panther-signal`). Orthogonal to `status`.
    # Rows that pre-date the column may hold NULL until the next sync
    # rewrites them -- every reader treats NULL as False.
    is_building_block: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
        index=True,
    )
    # HOW the rule works (#105 / teardown R06): rule | hunting | ml_job |
    # correlation | indicator_match | building_block. Keeps mechanism
    # out of event_types (what is observed) and language (query syntax).
    # See canonical.RULE_MODALITIES.
    rule_modality: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="rule",
        server_default="rule",
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
    )

    # ── Canonical taxonomy fields ────────────────────────────────────────
    # Values come from the canonical vocabulary defined in
    # `app/services/taxonomy/canonical.py`. Each list always contains at
    # least one value (`["unknown"]` if nothing could be resolved).
    #
    # Phase 3 (2026-05) dropped the legacy single-value siblings
    # (`platform`, `event_category`, `data_source_normalized`) and the
    # raw vendor-declared lists (`log_sources`, the prior
    # `data_sources`) and renamed `taxonomy_*` -> these final names.
    # See _migrate_taxonomy_phase_3 in app/database.py for the
    # idempotent migration.
    platforms: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    event_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # ── Use cases (analytic stories / vendor use-case tags) ──────────
    # Vendor-preserved display names. Populated for sources with an
    # explicit story/use-case concept: Splunk (`analytic_story` tags),
    # Elastic (`Use Case:` prefix tags), Sublime (`attack_types`
    # field). Other sources land as empty list. See docs/schema.md.
    use_cases: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # MITRE ATT&CK mapping
    mitre_tactics: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # ── MITRE ATT&CK Groups + Software (threat-actor mapping) ────────
    # Extracted from vendor `attack.g*` / `attack.s*` tag conventions.
    # G-IDs (e.g. "G0016" -> APT29) and S-IDs (e.g. "S0002" -> Mimikatz)
    # are preserved verbatim; the FE resolves them via the static
    # `mitre_lookup` service so display names ("APT29", "Mimikatz") stay
    # current with the ATT&CK release we ship. Populated for sources
    # that follow the ATT&CK tag convention (Sigma, LOLRMM); empty on
    # sources without native group/software tags. See docs/schema.md.
    mitre_groups: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    mitre_software: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

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

    # Vendor-authored investigation guide (markdown; Elastic `note`).
    investigation_guide: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Extracted observable fields (from detection logic parsing)
    extracted_fields_used: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_process_names: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_file_paths: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_registry_keys: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_network_indicators: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_source_tables: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_observables: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    query_complexity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
    )
    extracted_api_actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    extracted_target_resources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Rule quality score (0-100)
    quality_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    quality_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Original rule content
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)

    # Rule dates (from source)
    rule_created_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rule_modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Upstream commit touches, newest first (#127): [{sha, author, date, subject}]
    upstream_history: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Timestamps (sync timestamps)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # Id of the ingest run that last upserted this row (#31). Stale-row
    # cleanup deletes rows of a source whose run id is not the current
    # one -- immune to clock skew between app and DB and to two ingests
    # of the same source overlapping, which the old `updated_at <
    # ingest_start` watermark was not. NULL only on rows written before
    # the column existed; the next ingest of that source stamps them.
    sync_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Indexes for common queries
    __table_args__ = (
        Index("ix_detections_title", "title"),
        Index("ix_detections_source_file", "source_file"),
    )

    def __repr__(self) -> str:
        return f"<Detection(id={self.id}, source={self.source}, title={self.title[:50]})>"
