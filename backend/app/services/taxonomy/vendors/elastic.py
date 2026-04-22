"""Elastic Detection Rules resolver.

Four structured signals feed the taxonomy, in descending order of
precision:

  1. `rule.index` — index patterns (`logs-aws.cloudtrail*`,
     `logs-endpoint.events.process-*`) PLUS ESQL `FROM` clauses the
     parser pulled out of the query text.
  2. `metadata.integration` — integration names (`endpoint`, `aws`,
     `crowdstrike`).
  3. `rule.tags` — structured vocabulary (`"OS: Windows"`,
     `"Domain: Network"`, `"Data Source: Elastic Defend"`).
  4. `rule.type` — rule-level fallback (e.g. `machine_learning` rules
     have no index or FROM).

## Semantics

**Platforms.** `OS: <name>` tags are AUTHORITATIVE when present.
Elastic's rule authors use those tags to declare what OS the rule is
written for; the index-pattern / integration platform lists reflect
*capability*, not *intent*. So if a rule sits on `integration=endpoint`
(supports windows+linux+macos) but is tagged `OS: Windows`, we report
`[windows]` only. With no OS tags, we fall back to the union of
everything the other signals support.

**Event types.** UNION across all sources — index-pattern mappings,
integration mappings, tag mappings, rule-type mappings, AND the EQL
query head (`process where …` contributes `process_creation`). For
rules with `metadata.promotion = true` (Elastic's "promotion" rule
type — wraps EDR/external-SIEM alerts into Elastic alerts),
`platform_alert` is added to distinguish them from raw-telemetry rules
and from `alert_correlation` (the SIEM's OWN alert correlations, used
by `.alerts-security-*` higher-order rules).

**Data sources.** Straight union — a rule that queries endpoint events
AND calls out Sysmon AND tags CrowdStrike genuinely draws from all of
those sources.
"""

import re
from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("elastic")


# EQL queries begin with an event category keyword + `where`, e.g.
#   process where event.type == "start"
# OR they use `sequence` syntax with category blocks in brackets:
#   sequence by host.id with maxspan=5m
#     [process where event.action == "start"]
#     [network where event.type == "connection_attempt"]
# We need both forms. The regex matches EITHER the start of the query
# OR the inside of a `[` bracket — captures `process`, `file`,
# `network`, `registry`, `dns`, `library`, `authentication`, etc.
_EQL_CATEGORIES = re.compile(
    r"(?:^\s*|\[\s*)([a-z_]+)\s+where\b",
    re.IGNORECASE,
)

# KQL queries use `event.category:process` (structured field-colon
# syntax) instead of EQL's `<cat> where ...`. Extract the category
# value so KQL rules get a proper event_type.
_KQL_EVENT_CATEGORY = re.compile(
    r"event\.category\s*:\s*\"?([a-z_]+)\"?",
    re.IGNORECASE,
)


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
    rule_type = (extra.get("type") or "").lower().strip()
    language = (extra.get("language") or "").lower().strip()
    promotion = bool(extra.get("promotion", False))

    query = parsed.detection_logic_raw
    if isinstance(query, dict):
        query_text = query.get("query") or ""
    elif isinstance(query, str):
        query_text = query
    else:
        query_text = ""

    return _resolve_all_signals(
        indices=indices,
        integrations=integrations,
        tags=tags,
        rule_type=rule_type,
        language=language,
        query_text=query_text,
        promotion=promotion,
    )


def _resolve_all_signals(
    indices: list[str],
    integrations: list[str],
    tags: list[str],
    rule_type: str,
    language: str,
    query_text: str,
    promotion: bool,
) -> dict:
    """Walk every structured signal, union data_sources/event_types,
    and apply OS-tag precedence for platforms."""
    # Capability-scope set (widened by every matching signal).
    cap_platforms: set[str] = set()
    # Authoritative-intent set (populated only by `OS: *` tags).
    os_tag_platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    index_map = _MAPPING.get("index_patterns", {})
    integration_map = _MAPPING.get("integrations", {})
    tag_map = _MAPPING.get("tags", {})
    rule_type_map = _MAPPING.get("rule_types", {})
    eql_category_map = _MAPPING.get("eql_category_to_event_types", {})

    # ── Index patterns ──
    for idx in indices:
        if not isinstance(idx, str):
            continue
        idx_lower = idx.lower().strip()
        entry = index_map.get(idx_lower)
        if entry is None:
            for pattern, mapping in index_map.items():
                if _index_matches(idx_lower, pattern.lower()):
                    entry = mapping
                    break
        if entry:
            cap_platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # ── Integrations ──
    for integ in integrations:
        if not isinstance(integ, str):
            continue
        entry = integration_map.get(integ.lower().strip())
        if entry:
            cap_platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # ── Tags ──
    # `OS: X` tags contribute to `os_tag_platforms` (the authoritative
    # override bucket) AND to data_sources / event_types via the normal
    # tag-map entry. All other tag types (Domain, Data Source) feed the
    # capability-scope set like any other signal.
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tag_key = tag.lower().strip()
        entry = tag_map.get(tag_key)
        if entry:
            if tag_key.startswith("os:"):
                os_tag_platforms.update(entry.get("platforms") or [])
            else:
                cap_platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # ── Rule-type fallback (machine_learning, etc.) ──
    if rule_type:
        entry = rule_type_map.get(rule_type)
        if entry:
            cap_platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # ── EQL query categories ──
    # Elastic EQL rules express the event category in the query head
    # (`process where ...`) OR as blocks inside a `sequence` query
    # (`sequence ... [process where ...] [file where ...]`). Extract
    # all occurrences and map each to an event_type.
    if language == "eql" and query_text:
        for match in _EQL_CATEGORIES.finditer(query_text):
            category = match.group(1).lower()
            mapped = eql_category_map.get(category)
            if mapped:
                if isinstance(mapped, list):
                    event_types.update(mapped)
                else:
                    event_types.add(str(mapped))

    # ── KQL event.category: extraction ──
    # KQL queries (language=kuery / kql) don't have the EQL `<cat> where`
    # structure. They reference the category via `event.category:<x>`.
    # Same mapping applies.
    if language in ("kql", "kuery") and query_text:
        for match in _KQL_EVENT_CATEGORY.finditer(query_text):
            category = match.group(1).lower()
            mapped = eql_category_map.get(category)
            if mapped:
                if isinstance(mapped, list):
                    event_types.update(mapped)
                else:
                    event_types.add(str(mapped))

    # ── Promotion rules (Elastic wrapping external alerts) ──
    if promotion:
        event_types.add("platform_alert")

    # ── Platform resolution: OS tags override when present ──
    # If any `OS: *` tag matched, use that set exclusively — the rule
    # was authored for those specific OSes. Otherwise fall back to the
    # union of what the index/integration/tag signals say is possible.
    if os_tag_platforms:
        final_platforms = os_tag_platforms
    else:
        final_platforms = cap_platforms

    return {
        "platforms": final_platforms,
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
