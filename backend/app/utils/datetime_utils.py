"""Datetime helpers used across the backend.

The codebase stores naive UTC timestamps in SQLAlchemy ``DateTime`` columns
(no ``timezone=True``). ``datetime.utcnow()`` is deprecated in Python 3.12+;
the modern replacement ``datetime.now(timezone.utc)`` returns an *aware*
datetime, which would break comparisons against the existing naive column
data. ``utcnow()`` here returns naive UTC to keep the storage convention
unchanged while satisfying the deprecation.
"""

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Serialize a stored timestamp as zone-qualified ISO 8601 (#52).

    Storage is naive UTC, and ``datetime.isoformat()`` on a naive value
    emits ``2026-08-29T18:00:00`` with no designator -- which every
    JavaScript ``Date`` parser reads as LOCAL time. Public API responses
    must say what they mean: naive values are labelled UTC with a
    trailing ``Z``; aware values are converted to UTC first.
    """
    if value is None:
        return None
    if not isinstance(value, datetime):
        # A plain `date` has no time component to qualify (coverage
        # snapshot days); ISO date strings are unambiguous as-is.
        return value.isoformat()
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat() + "Z"
