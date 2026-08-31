"""Persisted computed artifacts (#81 / teardown S2.4).

The in-process corpus cache empties on every deploy, so the first
visitor after a deploy pays the full facets/statistics/filter scans
(the teardown measured 1.5s on the critical path). Heavy artifacts are
now also written here, keyed by cache key + corpus fingerprint: a
fresh process finds them at the fingerprint it observes and serves
warm immediately. Stale fingerprints are overwritten in place; the
table never grows past the set of persisted keys.
"""

from datetime import datetime

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow


class ComputedArtifact(Base):
    __tablename__ = "computed_artifacts"

    # repr() of the corpus-cache key tuple. Bounded set: only
    # allowlisted heavy computations persist.
    key: Mapped[str] = mapped_column(String(400), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(120), nullable=False)
    payload: Mapped[dict | list | str] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
