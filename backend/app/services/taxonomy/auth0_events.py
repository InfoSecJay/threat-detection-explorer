"""Auth0 log event type dictionary (issue #72).

Auth0 rules key on `data.type` codes (`s`, `f`, `fp`, `sapi`, ...).
`mappings/auth0_events.yaml` labels each code so the UI can say what
the event is; `lookup` mirrors `event_ids.lookup` for Windows IDs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_PATH = Path(__file__).resolve().parent / "mappings" / "auth0_events.yaml"

CATEGORIES: frozenset[str] = frozenset({"success", "failure", "warning", "limit"})


@dataclass(frozen=True)
class Auth0EventEntry:
    code: str
    label: str
    category: str


def _load(strict: bool = False) -> dict[str, Auth0EventEntry]:
    try:
        data = yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        if strict:
            raise
        logger.error("auth0_events.yaml unreadable (%s); lookups disabled", exc)
        return {}

    index: dict[str, Auth0EventEntry] = {}
    for raw_code, spec in (data.get("events") or {}).items():
        code = str(raw_code).strip()
        spec = spec or {}
        label = str(spec.get("label") or "")
        category = str(spec.get("category") or "")
        problems = []
        if not label:
            problems.append(f"code {code}: no label")
        if category not in CATEGORIES:
            problems.append(f"code {code}: category {category!r} not in {sorted(CATEGORIES)}")
        if code in index:
            problems.append(f"code {code}: duplicate")
        if problems:
            if strict:
                raise ValueError("auth0_events.yaml: " + "; ".join(problems))
            logger.warning("auth0_events.yaml: %s -- entry skipped", "; ".join(problems))
            continue
        index[code] = Auth0EventEntry(code=code, label=label, category=category)
    return index


AUTH0_EVENT_INDEX: dict[str, Auth0EventEntry] = _load()


def lookup(code: str) -> Auth0EventEntry | None:
    """Dictionary entry for an Auth0 `data.type` code, or None."""
    return AUTH0_EVENT_INDEX.get(str(code).strip().lower())


def is_auth0_event_code(code: str) -> bool:
    return lookup(code) is not None
