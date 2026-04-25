"""Datetime helpers used across the backend.

The codebase stores naive UTC timestamps in SQLAlchemy ``DateTime`` columns
(no ``timezone=True``). ``datetime.utcnow()`` is deprecated in Python 3.12+;
the modern replacement ``datetime.now(timezone.utc)`` returns an *aware*
datetime, which would break comparisons against the existing naive column
data. ``utcnow()`` here returns naive UTC to keep the storage convention
unchanged while satisfying the deprecation.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
