"""Alias index for detection permalinks (#86 / teardown F10).

Two alias classes point at a canonical detection id:

- ``legacy``: the v1 path-hash id (`sha256(source:file_path)`), so
  every link shared before the deterministic-id migration keeps
  resolving (the API answers 301 to the canonical id).
- ``rule_id``: the upstream rule id the vendor publishes, so people
  can link with the id their vendor uses
  (`/detections/c28c8fa1-...` -> canonical page).

Rows are written at ingest time and never garbage-collected: an alias
whose target row later disappears simply falls through to 404 (and,
once tombstones land, to the tombstone).
"""

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow
from datetime import datetime
from sqlalchemy import DateTime


class DetectionAlias(Base):
    __tablename__ = "detection_aliases"

    # The alias itself. Upstream rule ids are free-form (Panther dotted
    # names run long); 200 matches detections.rule_id.
    alias: Mapped[str] = mapped_column(String(200), primary_key=True)
    detection_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    # "legacy" (v1 path-hash id) or "rule_id" (upstream id).
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
