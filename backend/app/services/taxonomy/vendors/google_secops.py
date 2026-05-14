"""Google SecOps (Chronicle) resolver.

Chronicle YARA-L rules carry explicit `platform` and `data_source`
meta fields, which the parser surfaces in `parsed.extra`. Resolution
order:

  Tier 1 -- `extra["platform"]` -> canonical platform.
  Tier 2 -- `extra["data_source"]` -> canonical data_source + a
            default event_type (when the data source has an obvious
            associated activity, e.g. cloudtrail -> api_call).
  Tier 3 -- folder fallback. `rules/community/<vendor>/...` -- the
            top-level vendor folder hints at platform/data_source
            when the meta block is incomplete.

Always-includes is empty; Chronicle doesn't have a corpus-wide
event_type the way Sublime is always `email_message`.
"""

from typing import TYPE_CHECKING

from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule


_MAPPING = load_mapping("google_secops")


def _folder_hint(file_path: str) -> str:
    """Return the top-level vendor folder under `rules/community/`."""
    norm = file_path.replace("\\", "/").lower()
    marker = "rules/community/"
    idx = norm.find(marker)
    if idx < 0:
        return ""
    rest = norm[idx + len(marker):]
    parts = rest.split("/")
    return parts[0] if parts else ""


def resolve(parsed: "ParsedRule") -> dict:
    extra = parsed.extra or {}

    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    # Tier 1: explicit `platform` meta.
    platform_raw = (extra.get("platform") or "").lower().strip()
    if platform_raw:
        entry = (_MAPPING.get("by_platform") or {}).get(platform_raw)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Tier 2: explicit `data_source` meta.
    data_source_raw = (extra.get("data_source") or "").lower().strip()
    if data_source_raw:
        entry = (_MAPPING.get("by_data_source") or {}).get(data_source_raw)
        if entry:
            platforms.update(entry.get("platforms") or [])
            data_sources.update(entry.get("data_sources") or [])
            event_types.update(entry.get("event_types") or [])

    # Tier 3: folder fallback when meta block didn't fully resolve.
    if not platforms or not data_sources:
        folder = _folder_hint(parsed.file_path)
        if folder:
            entry = (_MAPPING.get("by_folder") or {}).get(folder)
            if entry:
                platforms.update(entry.get("platforms") or [])
                data_sources.update(entry.get("data_sources") or [])
                event_types.update(entry.get("event_types") or [])

    # Always-includes (empty for Chronicle; kept for parity).
    always = _MAPPING.get("always_includes") or {}
    platforms.update(always.get("platforms") or [])
    data_sources.update(always.get("data_sources") or [])
    event_types.update(always.get("event_types") or [])

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
