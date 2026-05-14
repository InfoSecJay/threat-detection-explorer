"""Okta customer-detections resolver.

Trivial -- every Okta rule maps to (okta, okta_system_log,
authentication). The `always_includes` block in the mapping YAML
provides the only signal. Kept as a separate vendor module rather
than a special case in `resolver.py` for parity with the other
8 sources.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("okta")


def resolve(parsed: "ParsedRule") -> dict:
    always = _MAPPING.get("always_includes") or {}
    return {
        "platforms": set(always.get("platforms") or []),
        "data_sources": set(always.get("data_sources") or []),
        "event_types": set(always.get("event_types") or []),
    }
