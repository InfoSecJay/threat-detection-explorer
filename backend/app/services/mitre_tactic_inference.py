"""Technique -> tactic inference from the local MITRE ATT&CK cache.

Vendor rules often ship technique IDs (T1059.001) without an
explicit tactic ID (TA0002). Historically each parser hardcoded a
small inference table -- Splunk had ~30 parent techniques mapped,
which meant 45% of the 1988-rule Splunk corpus had techniques but
no tactics (the technique was outside the table).

This module loads the CANONICAL technique -> tactic map from the
STIX cache we already keep at data/mitre_attack.json (all 835
techniques + sub-techniques). One place to import from, one place
to keep current.

Design:
- Lazy load on first call, cached for the process lifetime. Parsers
  don't take an async DB session; this stays a pure sync helper.
- Sub-technique fallback: if T1059.001 isn't in the cache directly,
  fall back to the parent T1059 (defensive against a stale cache).
- Never raises: on any load error we log once and infer nothing.
  Empty inference is strictly better than crashing the parser.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

_CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "mitre_attack.json"

_LOADED = False
_TECHNIQUE_TO_TACTICS: dict[str, list[str]] = {}


def _load() -> None:
    """Populate _TECHNIQUE_TO_TACTICS from the STIX cache. Idempotent."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True  # even on failure so we don't retry the load per call
    try:
        with _CACHE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.warning(
            f"MITRE cache not found at {_CACHE_PATH}; "
            f"tactic inference will be empty until a sync populates it"
        )
        return
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(
            f"MITRE cache load failed ({type(e).__name__}: {e}); "
            f"tactic inference disabled for this process"
        )
        return

    techs = data.get("techniques", {}) if isinstance(data, dict) else {}
    for tid, info in techs.items():
        if not isinstance(info, dict):
            continue
        tactics = info.get("tactics") or []
        if isinstance(tactics, list) and tactics:
            # Keep insertion order stable to avoid churn in stored lists.
            _TECHNIQUE_TO_TACTICS[str(tid).upper()] = [
                str(t).upper() for t in tactics if t
            ]
    logger.info(
        f"mitre_tactic_inference: loaded {len(_TECHNIQUE_TO_TACTICS)} "
        f"technique -> tactic mappings from {_CACHE_PATH.name}"
    )


def infer_tactics(techniques: Iterable[str]) -> list[str]:
    """Return the list of tactic IDs (TA0XXX) implied by these techniques.

    - Techniques with no cached mapping contribute nothing (safe).
    - Sub-technique (T1059.001) falls back to parent (T1059) if the
      sub isn't in the cache directly. Prevents stale-cache silent
      misses right after a MITRE update.
    - Output is deduplicated in first-seen order so JSON storage
      stays deterministic.
    """
    _load()
    if not _TECHNIQUE_TO_TACTICS:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for tech in techniques or ():
        if not tech:
            continue
        key = str(tech).upper().strip()
        cached: Optional[list[str]] = _TECHNIQUE_TO_TACTICS.get(key)
        if cached is None and "." in key:
            # Sub-technique not directly cached -- fall back to parent
            cached = _TECHNIQUE_TO_TACTICS.get(key.split(".", 1)[0])
        if not cached:
            continue
        for t in cached:
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def reset_cache_for_tests() -> None:
    """Test hook -- forces re-load on next call. Never called in prod."""
    global _LOADED
    _LOADED = False
    _TECHNIQUE_TO_TACTICS.clear()
