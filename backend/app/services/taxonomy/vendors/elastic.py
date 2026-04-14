"""Elastic Detection Rules resolver.

Elastic rules carry two structured signals about telemetry source:

  - `metadata.integration` (list of plugin names like "endpoint", "aws",
    "crowdstrike") — coarse-grained
  - `rule.index` (list of Elasticsearch index patterns like
    `logs-aws.cloudtrail*`, `logs-endpoint.events.process-*`) — fine-grained,
    most reliable

We extract index patterns first (most precise mappings), then fall back
to integrations for any dimension still empty. A single rule can span
many sources (Elastic's cross-platform rules often list 6+ index
patterns); the resolver unions across all matches.

`event_types` are resolved primarily from the index pattern (e.g.
`process-*` → process_creation), and as a fallback from the rule's
language hint (eql tends to mean process events; esql tends to mean
analytical/audit queries).
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("elastic")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Elastic rule."""
    extra = parsed.extra or {}
    log_source = parsed.log_source or {}

    indices: list[str] = []
    for src in (extra.get("index"), log_source.get("indices"), log_source.get("index")):
        if isinstance(src, list):
            indices.extend(s for s in src if isinstance(s, str))
        elif isinstance(src, str):
            indices.append(src)

    integrations = extra.get("integration") or []
    if isinstance(integrations, str):
        integrations = [integrations]

    return _resolve_from_indices_and_integrations(indices, integrations)


def _resolve_from_indices_and_integrations(
    indices: list[str], integrations: list[str]
) -> dict:
    """Walk index patterns + integrations against the mapping and union
    canonical values across all matches."""
    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    index_map = _MAPPING.get("index_patterns", {})
    integration_map = _MAPPING.get("integrations", {})

    for idx in indices:
        idx_lower = idx.lower().strip()
        # Try exact match first, then prefix match (since patterns end in *)
        if idx_lower in index_map:
            entry = index_map[idx_lower]
        else:
            entry = None
            for pattern, mapping in index_map.items():
                if _index_matches(idx_lower, pattern.lower()):
                    entry = mapping
                    break
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    for integ in integrations:
        if not isinstance(integ, str):
            continue
        entry = integration_map.get(integ.lower().strip())
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }


def _index_matches(actual: str, pattern: str) -> bool:
    """Check if an actual index name matches a wildcard pattern.

    Patterns end with `*` — we match by stripping the wildcard and using
    a prefix check. Both inputs are already lowercased.
    """
    if pattern.endswith("*"):
        return actual.startswith(pattern.rstrip("*"))
    return actual == pattern
