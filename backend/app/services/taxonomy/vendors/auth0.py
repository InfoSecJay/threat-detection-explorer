"""Auth0 customer-detections resolver.

Trivial -- every Auth0 rule maps to (auth0, auth0_logs,
authentication). The `always_includes` block in the mapping YAML
provides the only signal (same shape as the Okta resolver). Kept as
a separate vendor module for parity with the other sources.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("auth0")


def resolve(parsed: "ParsedRule") -> dict:
    always = _MAPPING.get("always_includes") or {}
    return {
        "platforms": set(always.get("platforms") or []),
        "data_sources": set(always.get("data_sources") or []),
        "event_types": set(always.get("event_types") or []),
    }
