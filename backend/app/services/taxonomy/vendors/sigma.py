"""Sigma resolver.

Sigma rules use a `logsource` block with `product`, `service`, and
`category` keys. We try the most specific key first
(`product/service/category`), falling back to less specific combinations,
and union the canonical values from all matching mapping entries.

Example logsource:
    product: windows
    category: process_creation
    service: powershell

Lookup attempts (most specific first):
    1. windows/powershell/process_creation
    2. windows/powershell
    3. windows/process_creation
    4. windows
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("sigma")


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed Sigma rule."""
    log_source = parsed.log_source or {}
    product = (log_source.get("product") or "").lower().strip()
    service = (log_source.get("service") or "").lower().strip()
    category = (log_source.get("category") or "").lower().strip()

    # Try the most specific key first; first match wins.
    keys_to_try = []
    if product and service and category:
        keys_to_try.append(f"{product}/{service}/{category}")
    if product and service:
        keys_to_try.append(f"{product}/{service}")
    if product and category:
        keys_to_try.append(f"{product}/{category}")
    if product:
        keys_to_try.append(product)

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    by_key = _MAPPING.get("by_key", {})

    # First pass: find the MOST SPECIFIC matching key and take its values.
    # Union-across-multiple-matches was a bug — a rule with
    # `product=linux, category=process_creation` was picking up data_sources
    # from both `linux/process_creation` AND `linux` bare, giving spurious
    # multi-source results like [auditd, osquery, linux_syslog] even when
    # Sigma said nothing about the data source.
    matched_key: str | None = None
    for key in keys_to_try:
        entry = by_key.get(key)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])
            matched_key = key
            break

    # Second pass: only fills dimensions the most-specific match left empty,
    # by looking at less-specific fallback entries. Lets something like
    # `linux/sshd` (which omits event_types) pull event_types from `linux`
    # bare, but NEVER overwrites what the specific match already said.
    if matched_key is not None and not (platforms and data_sources and event_types):
        for key in keys_to_try:
            if key == matched_key:
                continue
            entry = by_key.get(key)
            if not entry:
                continue
            if not platforms:
                platforms.update(entry.get("platforms") or [])
            if not data_sources:
                data_sources.update(entry.get("data_sources") or [])
            if not event_types:
                event_types.update(entry.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
