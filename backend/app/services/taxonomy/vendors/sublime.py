"""Sublime resolver.

Sublime detection rules operate on email logs only. There is no per-rule
data-source field in the YAML; every rule implicitly inspects email
message metadata. So this resolver always returns the same canonical
values from `mappings/sublime.yaml`'s `always_includes` block. The
`attack_types` and `detection_methods` fields on Sublime rules are
meaningful in their own right, but per the design decision they are not
modeled in the taxonomy (Issue 2 scope: telemetry source, not threat
classification).
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("sublime")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Sublime rule.

    Always returns the same canonical values; Sublime is email-only.
    """
    always = _MAPPING.get("always_includes") or {}
    return {
        "platforms": set(always.get("platforms") or []),
        "data_sources": set(always.get("data_sources") or []),
        "event_types": set(always.get("event_types") or []),
    }
