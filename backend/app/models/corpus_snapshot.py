"""Nightly corpus snapshots (#94 / teardown S5.1).

The longitudinal record is the one asset a competitor starting
tomorrow cannot replicate -- but it only exists if we keep it. One row
per (snapshot_date, source) holding the full normalized corpus of that
source as gzip-compressed JSONL, written by the worker at the end of
every successful full sync.

Volume: the whole corpus serializes to ~40MB raw / ~5-6MB gzipped per
night, dominated by raw_content. A year is ~2GB in Postgres -- cheap
against what it buys (tombstones, historical digests, quarterly
coverage reports, "state of the corpus on any past date"). Revisit
retention only if that math changes.
"""

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow


class CorpusSnapshot(Base):
    __tablename__ = "corpus_snapshots"
    __table_args__ = (
        UniqueConstraint("snapshot_date", "source", name="uq_corpus_snapshot_day_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # gzip-compressed JSONL: one JSON object per rule, every column of
    # the detections row except sync bookkeeping.
    payload_gz: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
