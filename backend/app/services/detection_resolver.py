"""Resolve any detection identifier to its row (#86 / teardown F10).

Accepts the canonical id, a legacy v1 path-hash id, or an upstream
rule id, in that precedence. Used by every endpoint that takes a
detection id (detail, related, prerender, OG card) so old links and
vendor ids work everywhere; the detail route additionally 301s when
the match came through an alias, so clients converge on the canonical
URL.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.detection_alias import DetectionAlias


async def resolve_detection(
    db: AsyncSession, identifier: str
) -> tuple[Optional[Detection], bool]:
    """Return ``(detection, via_alias)`` for any known identifier.

    ``via_alias`` is True when the identifier was NOT the canonical id
    (the caller may 301 to the canonical URL). Unknown identifiers
    return ``(None, False)``.
    """
    d = await db.get(Detection, identifier)
    if d is not None:
        return d, False

    row = (
        await db.execute(
            select(DetectionAlias.detection_id).where(DetectionAlias.alias == identifier)
        )
    ).scalar_one_or_none()
    if row is not None:
        d = await db.get(Detection, row)
        if d is not None:
            return d, True

    # Upstream rule ids resolve even before the alias table is
    # populated for a source (and cover case-variant links).
    d = (
        await db.execute(
            select(Detection).where(Detection.rule_id == identifier).limit(1)
        )
    ).scalar_one_or_none()
    if d is not None:
        return d, True
    return None, False
