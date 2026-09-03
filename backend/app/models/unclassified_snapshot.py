"""Daily unclassified-count snapshot (teardown R14 / #112).

One row per (snapshot_date, source, field): how many of that source's
rules carried `unknown` in that field on that day. Written by the
worker after every successful full sync, next to the MITRE coverage
snapshot; `/api/methodology/unclassified` reads the history to show
the burn-down. ~13 sources x 7 fields ~= 100 rows/day.
"""

from datetime import date

from sqlalchemy import Date, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UnclassifiedSnapshot(Base):
    __tablename__ = "unclassified_snapshot"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_date", "source", "field",
            name="uq_unclassified_snapshot_day_source_field",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    field: Mapped[str] = mapped_column(String(40), nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Denominator on that day, so a percentage survives corpus growth.
    total_rules: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
