"""Panther Labs `panther-analysis` taxonomy resolver.

Panther rules declare one or more `LogTypes:` in their YAML metadata.
The parser puts the raw list on `parsed.extra["log_types"]`. We look
each up in `mappings/panther.yaml` and UNION the results — a
multi-LogType rule like `LogTypes: [OneLogin.Events, AWS.CloudTrail]`
resolves to platforms=[aws, onelogin] etc.

Resolution order per LogType:
  1. Exact match in `by_log_type`.
  2. Prefix match in `by_prefix` (safety net for new subtypes in
     known vendor families).
  3. Skip (contributes nothing to the union).

Correlation rules ship without LogTypes; they fall through to
`correlation_rule_default` so they don't emit [unknown].
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("panther")


def _lookup(log_type: str) -> dict:
    """Return the mapping entry for a LogType, or {} on miss."""
    by_type = _MAPPING.get("by_log_type") or {}
    if log_type in by_type:
        return by_type[log_type]

    # Prefix fallback: first matching prefix wins.
    by_prefix = _MAPPING.get("by_prefix") or {}
    for prefix, entry in by_prefix.items():
        if log_type.startswith(prefix):
            return entry
    return {}


def resolve(parsed: "ParsedRule") -> dict:
    extra = parsed.extra or {}
    log_types = extra.get("log_types") or []
    analysis_type = extra.get("analysis_type") or "rule"

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    for lt in log_types:
        if not isinstance(lt, str):
            continue
        entry = _lookup(lt)
        if not entry:
            continue
        platforms.update(entry.get("platforms") or [])
        data_sources.update(entry.get("data_sources") or [])
        event_types.update(entry.get("event_types") or [])

    # A rule with no LogTypes (some Auth0.* rules, #57) is still named
    # after its log family: try the RuleID prefix before giving up.
    if not platforms:
        rule_id = extra.get("rule_id") or extra.get("id") or ""
        if isinstance(rule_id, str) and "." in rule_id:
            entry = _lookup(rule_id.split(".")[0] + ".")
            if entry:
                platforms.update(entry.get("platforms") or [])
                data_sources.update(entry.get("data_sources") or [])
                event_types.update(entry.get("event_types") or [])

    # Correlation rules have no LogTypes; use the mapping's default so
    # they don't fall through to [unknown].
    if not platforms and analysis_type == "correlation_rule":
        default = _MAPPING.get("correlation_rule_default") or {}
        platforms.update(default.get("platforms") or [])
        data_sources.update(default.get("data_sources") or [])
        event_types.update(default.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
