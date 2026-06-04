"""Top-level dispatcher: route a parsed rule to its vendor-specific resolver.

Each repository has its own `resolve(parsed)` function in
`taxonomy/vendors/<repo>.py` that knows how to walk the vendor-specific
schema and apply the YAML mapping for that repo. This module just maps
repo names to those functions and provides the unified entry point.

Public API:

    resolve_for_repo(repo_name: str, parsed: ParsedRule) -> dict
        Returns {
            "platforms": [...],
            "data_sources": [...],
            "event_types": [...],
            "matched": bool,           # True if any dimension was resolved from vendor data
            "fingerprint": str,        # stable signature of the input for grouping unmapped rules
        }

The `matched` signal separates "the vendor didn't provide enough info"
(matched=False, values fall back to [UNKNOWN]) from "the mapping tables
don't cover this logsource yet" — both historically looked the same.
It's the key input to coverage metrics + drift notifications.
"""

from typing import TYPE_CHECKING, Callable

from app.services.taxonomy.canonical import UNKNOWN, data_source_applies
from app.services.taxonomy.vendors import (
    auth0,
    elastic,
    elastic_hunting,
    elastic_protections,
    google_secops,
    lolrmm,
    okta,
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
    "google_secops": google_secops.resolve,
    "okta": okta.resolve,
    "auth0": auth0.resolve,
}


def resolve_for_repo(repo_name: str, parsed: "ParsedRule") -> dict:
    """Resolve canonical platforms/data_sources/event_types for a parsed rule.

    Args:
        repo_name: The repository identifier (must match one of the keys
            in `_VENDOR_RESOLVERS`).
        parsed: The vendor's `ParsedRule` instance from the parser.

    Returns:
        A dict with five entries:
          - `platforms`: canonical platform identifiers (list[str])
          - `data_sources`: canonical data source identifiers (list[str])
          - `event_types`: canonical event type identifiers (list[str])
          - `matched`: True if the vendor resolver produced ANY canonical
            value (before UNKNOWN fallback). False means the logsource
            signature didn't hit any mapping — feeds coverage metrics.
          - `fingerprint`: stable short string identifying this rule's
            logsource signature. Used to group unmapped rules in drift
            reports so identical misses become one ticket, not many.

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

    # Capture raw values BEFORE applying the UNKNOWN fallback so we can
    # tell "vendor data produced nothing" from "vendor data was mapped
    # to canonical values". This is the definition of `matched` that
    # feeds the coverage metrics.
    raw_platforms = result.get("platforms") or []
    raw_data_sources = result.get("data_sources") or []
    raw_event_types = result.get("event_types") or []
    matched = bool(raw_platforms or raw_data_sources or raw_event_types)

    # Narrow data_sources to those whose producing-platforms intersect
    # with the rule's final platform set. Fixes the "capability bleed"
    # where an integration that supports both windows + linux telemetry
    # (e.g., Elastic `system` → [linux_syslog, windows_security_event_log])
    # leaked the non-applicable data_source onto a Windows-scoped rule.
    # See canonical.data_source_applies for the semantics — permissive
    # on unknown/cross_platform to avoid over-pruning.
    platform_set = set(raw_platforms) if isinstance(raw_platforms, (list, set, frozenset)) else set()
    narrowed_data_sources = [
        ds for ds in _iter_strings(raw_data_sources)
        if data_source_applies(ds, platform_set)
    ]
    # Defensive: if narrowing would leave data_sources empty (and we
    # originally had some), keep the originals. Better to show a
    # capability list than to lose data entirely because our mapping
    # was incomplete for an edge case.
    if raw_data_sources and not narrowed_data_sources:
        narrowed_data_sources = list(_iter_strings(raw_data_sources))

    return {
        "platforms": _ensure_list(raw_platforms),
        "data_sources": _ensure_list(narrowed_data_sources),
        "event_types": _ensure_list(raw_event_types),
        "matched": matched,
        "fingerprint": _compute_fingerprint(repo_name, parsed),
    }


def _iter_strings(value) -> list[str]:
    """Coerce a possibly-set / possibly-list value to a list of strings."""
    if not value:
        return []
    if isinstance(value, (set, frozenset, list)):
        return [str(v) for v in value]
    return [str(value)]


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


def _compute_fingerprint(repo_name: str, parsed: "ParsedRule") -> str:
    """Build a stable short string representing the rule's logsource signature.

    Used to group unmapped rules in drift reports: identical fingerprints
    collapse to one row, so "50 new Sigma rules with product=foo/service=bar"
    surfaces as one entry, not 50. Format varies per vendor but the key
    invariant is stability — the same input always produces the same
    fingerprint.
    """
    ls = parsed.log_source or {}
    extra = parsed.extra or {}

    if repo_name == "sigma":
        return (
            f"sigma:{ls.get('product') or '-'}"
            f"/{ls.get('service') or '-'}"
            f"/{ls.get('category') or '-'}"
        )
    if repo_name in ("elastic", "elastic_hunting", "elastic_protections"):
        indices = ls.get("indices") or extra.get("index") or []
        integrations = extra.get("integration") or []
        if isinstance(integrations, str):
            integrations = [integrations]
        idx = ",".join(sorted(str(i).lower() for i in indices)) if indices else "-"
        itg = ",".join(sorted(str(i).lower() for i in integrations)) if integrations else "-"
        return f"{repo_name}:{idx}|integ:{itg}"
    if repo_name == "splunk":
        ds = extra.get("data_source") or []
        if isinstance(ds, str):
            ds = [ds]
        labels = ",".join(sorted(str(d).lower() for d in ds)) if ds else "-"
        return f"splunk:{labels}"
    if repo_name == "sentinel":
        connectors = extra.get("requiredDataConnectors") or []
        connector_ids: list[str] = []
        data_types: list[str] = []
        for c in connectors:
            if isinstance(c, dict):
                cid = c.get("connectorId")
                if cid:
                    connector_ids.append(str(cid).lower())
                for dt in c.get("dataTypes") or []:
                    data_types.append(str(dt).lower())
        c_str = ",".join(sorted(set(connector_ids))) if connector_ids else "-"
        d_str = ",".join(sorted(set(data_types))) if data_types else "-"
        return f"sentinel:{c_str}|dt:{d_str}"
    if repo_name == "lolrmm":
        return f"lolrmm:{ls.get('product') or '-'}"
    if repo_name == "sublime":
        return "sublime:email"
    return f"{repo_name}:-"
