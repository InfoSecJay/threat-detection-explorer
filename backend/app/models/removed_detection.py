"""Tombstones for rules removed upstream (#87 / teardown F11).

When the stale-rule cleanup deletes a row (its source file vanished
from the upstream repo), the full final row is preserved here first.
A previously-valid rule URL then serves "tracked until X, removed from
<repo>; here is the last version we saw and current rules for the same
technique" instead of a 404 -- a page only the site's own history can
produce.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, JSON, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow


class RemovedDetection(Base):
    __tablename__ = "removed_detections"

    # Same id the live row had; permalinks keep resolving.
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)
    source_file: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # gzip JSON of the final full row (same serializer as corpus
    # snapshots) -- the "last version we saw".
    payload_gz: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
