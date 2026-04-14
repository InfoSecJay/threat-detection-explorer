"""Top-level dispatcher: route a parsed rule to its vendor-specific resolver.

Each repository has its own `resolve(parsed)` function in
`taxonomy/vendors/<repo>.py` that knows how to walk the vendor-specific
schema and apply the YAML mapping for that repo. This module just maps
repo names to those functions and provides the unified entry point.

Public API:

    resolve_for_repo(repo_name: str, parsed: ParsedRule) -> dict
        Returns {"platforms": [...], "data_sources": [...], "event_types": [...]}
        with all values from the canonical vocabulary (or "unknown").
"""

from typing import TYPE_CHECKING, Callable

from app.services.taxonomy.canonical import UNKNOWN
from app.services.taxonomy.vendors import (
    elastic,
    elastic_hunting,
    elastic_protections,
    lolrmm,
    sentinel,
    sigma,
    splunk,
    sublime,
)

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


# Maps `repo_name` (the same string used everywhere else: `sigma`,
# `elastic`, `splunk`, `sublime`, `elastic_protections`, `lolrmm`,
# `elastic_hunting`, `sentinel`) to the resolver function that knows
# how to interpret that vendor's parsed-rule shape.
_VENDOR_RESOLVERS: dict[str, Callable[["ParsedRule"], dict]] = {
    "sigma": sigma.resolve,
    "elastic": elastic.resolve,
    "splunk": splunk.resolve,
    "sublime": sublime.resolve,
    "elastic_protections": elastic_protections.resolve,
    "lolrmm": lolrmm.resolve,
    "elastic_hunting": elastic_hunting.resolve,
    "sentinel": sentinel.resolve,
}


def resolve_for_repo(repo_name: str, parsed: "ParsedRule") -> dict:
    """Resolve canonical platforms/data_sources/event_types for a parsed rule.

    Args:
        repo_name: The repository identifier (must match one of the keys
            in `_VENDOR_RESOLVERS`).
        parsed: The vendor's `ParsedRule` instance from the parser.

    Returns:
        A dict with three list[str] entries:
          - `platforms`: canonical platform identifiers
          - `data_sources`: canonical data source identifiers
          - `event_types`: canonical event type identifiers

        Each list is sorted, deduplicated, and contains values only from
        the canonical vocabulary in `taxonomy.canonical`. If the vendor
        data didn't supply enough info to determine a value, the list
        contains `["unknown"]` so the field is never silently empty.

    Raises:
        ValueError: if `repo_name` is not a recognized repository.
    """
    resolver = _VENDOR_RESOLVERS.get(repo_name)
    if resolver is None:
        raise ValueError(
            f"No taxonomy resolver registered for repo {repo_name!r}. "
            f"Known repos: {sorted(_VENDOR_RESOLVERS)}"
        )

    result = resolver(parsed)

    # Defensive: ensure the resolver returned the expected shape and
    # apply unknown fallback. Vendor resolvers SHOULD do this themselves
    # but we double-check here so a bug in one resolver can't cause an
    # ingestion-blocking exception downstream.
    return {
        "platforms": _ensure_list(result.get("platforms")),
        "data_sources": _ensure_list(result.get("data_sources")),
        "event_types": _ensure_list(result.get("event_types")),
    }


def _ensure_list(value) -> list[str]:
    """Normalize a possibly-None or possibly-set value to a sorted list,
    falling back to [UNKNOWN] if empty."""
    if not value:
        return [UNKNOWN]
    if isinstance(value, (set, frozenset)):
        value = sorted(value)
    elif isinstance(value, list):
        # Preserve dedup but keep stable ordering
        value = sorted(set(value))
    else:
        value = [str(value)]
    return value if value else [UNKNOWN]
