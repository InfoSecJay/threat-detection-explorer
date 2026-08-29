"""Shared YAML loading + canonical validation helpers.

Vendor resolvers call `load_mapping("sigma")` once at module import time
to get a dict of mapping rules from `mappings/sigma.yaml`. Validation
warnings are logged for any mapping that references a non-canonical
platform / data_source / event_type, so typos in the YAML surface early
instead of silently writing garbage to the database.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

from app.services.taxonomy.canonical import (
    DATA_SOURCES,
    EVENT_TYPES,
    PLATFORMS,
)

logger = logging.getLogger(__name__)

_MAPPINGS_DIR = Path(__file__).resolve().parent / "mappings"


def load_mapping(vendor: str, strict: bool = False) -> dict[str, Any]:
    """Load `mappings/<vendor>.yaml` and validate its referenced values.

    Returns the parsed YAML as a dict. Logs (but does not raise) for any
    referenced platform/data_source/event_type that isn't in the canonical
    vocabulary — that way a typo in a mapping file produces a loud warning
    in the worker logs at startup but doesn't crash ingestion.

    `strict=True` raises `ValueError` instead. The test suite loads every
    mapping this way (`tests/test_services/test_mapping_integrity.py`)
    because a warning is not a gate: `endpoint_behavior` shipped to
    production as a non-canonical event_type on 63 rules before anyone
    read the worker log (issue #42).
    """
    path = _MAPPINGS_DIR / f"{vendor}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"Taxonomy mapping not found: {path}. "
            f"Add the file or update the vendor resolver."
        )

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    _validate_mapping(vendor, data, strict=strict)
    return data


def _validate_mapping(vendor: str, data: dict[str, Any], strict: bool = False) -> None:
    """Walk a parsed mapping and warn (or raise, when strict) about any
    non-canonical values."""
    bad_platforms: set[str] = set()
    bad_data_sources: set[str] = set()
    bad_event_types: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "platforms" and isinstance(value, list):
                    bad_platforms.update(v for v in value if v not in PLATFORMS)
                elif key == "data_sources" and isinstance(value, list):
                    bad_data_sources.update(v for v in value if v not in DATA_SOURCES)
                elif key == "event_types" and isinstance(value, list):
                    bad_event_types.update(v for v in value if v not in EVENT_TYPES)
                else:
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(data)

    for kind, bad in (
        ("platforms", bad_platforms),
        ("data_sources", bad_data_sources),
        ("event_types", bad_event_types),
    ):
        if bad:
            message = (
                f"Mapping {vendor}.yaml references non-canonical {kind}: "
                f"{sorted(bad)}. Add to canonical.py or fix the typo."
            )
            if strict:
                raise ValueError(message)
            logger.warning(message)
