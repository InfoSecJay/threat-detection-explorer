"""Elastic Detection Rules resolver.

Elastic rules carry four structured signals about telemetry source, in
descending order of precision:

  1. `rule.index` — index patterns (`logs-aws.cloudtrail*`,
     `logs-endpoint.events.process-*`) + ESQL `FROM` clauses extracted
     by the parser.
  2. `metadata.integration` — integration plugin names (`endpoint`,
     `aws`, `crowdstrike`) — coarser than index, still structured.
  3. `rule.tags` — structured tag vocabulary like `"OS: Windows"`,
     `"Domain: Network"`, `"Data Source: Elastic Defend"`.
  4. `rule.type` — for types like `machine_learning` that have neither
     index nor FROM clause.

The resolver unions canonical values across all signals. A rule can
legitimately span multiple sources (Elastic's cross-platform rules
often list 6+ index patterns); tags tend to be authoritative when they
specify an OS or Data Source; rule_type is the last resort.
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

    tags = parsed.tags or []
    rule_type = extra.get("type") or ""

    return _resolve_all_signals(indices, integrations, tags, rule_type)


def _resolve_all_signals(
    indices: list[str],
    integrations: list[str],
    tags: list[str],
    rule_type: str,
) -> dict:
    """Walk every structured signal and union canonical values."""
    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    index_map = _MAPPING.get("index_patterns", {})
    integration_map = _MAPPING.get("integrations", {})
    tag_map = _MAPPING.get("tags", {})
    rule_type_map = _MAPPING.get("rule_types", {})

    for idx in indices:
        if not isinstance(idx, str):
            continue
        idx_lower = idx.lower().strip()
        # Try exact match first, then prefix match (since patterns end in *)
        entry = index_map.get(idx_lower)
        if entry is None:
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

    for tag in tags:
        if not isinstance(tag, str):
            continue
        entry = tag_map.get(tag.lower().strip())
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Rule-type fallback: applies independently of the other signals so
    # an ML rule that ALSO has an integration picks up both the
    # integration's platform AND the ml_detection event_type.
    if rule_type:
        entry = rule_type_map.get(rule_type.lower().strip())
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
