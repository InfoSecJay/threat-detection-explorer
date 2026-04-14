"""Taxonomy module: normalized telemetry-source classification.

Public API:

    from app.services.taxonomy import resolve_for_repo, UNKNOWN
    result = resolve_for_repo("sigma", parsed_rule)
    # → {"platforms": [...], "data_sources": [...], "event_types": [...]}

See docs/taxonomy.md for the full design rationale and onboarding guide.
"""

from app.services.taxonomy.canonical import (
    DATA_SOURCES,
    EVENT_TYPES,
    PLATFORMS,
    UNKNOWN,
    is_canonical_data_source,
    is_canonical_event_type,
    is_canonical_platform,
)
from app.services.taxonomy.resolver import resolve_for_repo

__all__ = [
    "DATA_SOURCES",
    "EVENT_TYPES",
    "PLATFORMS",
    "UNKNOWN",
    "is_canonical_data_source",
    "is_canonical_event_type",
    "is_canonical_platform",
    "resolve_for_repo",
]
