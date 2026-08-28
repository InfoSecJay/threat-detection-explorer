"""MITRE coverage snapshot model (issue #9).

One row per (snapshot_date, technique_id, source): how many rules in
that source tagged that technique on that day. Written by the worker
at the end of every successful full sync; the newly-covered endpoint
diffs today against a baseline N days back to surface the
"Splunk just picked up T1651" signal.

Volume: ~800 covered techniques x ~13 sources ~= 5-6k rows/day, a few
MB/year — no retention policy needed yet.
"""

from datetime import date

from sqlalchemy import Date, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MitreCoverageSnapshot(Base):
    """Daily technique x source rule-count snapshot."""

    __tablename__ = "mitre_coverage_snapshot"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_date", "technique_id", "source",
            name="uq_coverage_snapshot_day_technique_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
