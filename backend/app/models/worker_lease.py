"""Single-flight lease for the sync worker (issue #36).

Railway briefly runs the old and new worker containers side by side
during a deploy. Both share the repos volume, so two workers running
syncs at once is an rmtree-vs-clone race. The lease makes "who may run
sync jobs" a database fact: exactly one row (`id='sync'`), owned by one
worker, kept alive by a heartbeat. A worker that does not hold it stays
in standby and claims nothing; a worker that takes it over knows every
`running` job row belongs to a dead holder and can requeue immediately
instead of waiting out the stuck-job timeout.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.datetime_utils import utcnow


class WorkerLease(Base):
    __tablename__ = "worker_leases"

    # Lease name; only "sync" exists today.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    # Holder identity: hostname:pid:nonce, informational.
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    # Renewed by the holder; a lease whose heartbeat is older than the
    # TTL is dead and may be taken over.
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    def __repr__(self) -> str:
        return f"<WorkerLease(id={self.id}, owner={self.owner}, heartbeat_at={self.heartbeat_at})>"
