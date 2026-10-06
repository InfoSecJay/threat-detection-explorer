"""Result-row snippets for `content:` hits (DX-12 / #167).

Bare words never reach rule bodies; `content:` / `raw:` / `logic:` do,
and a `content:citrix` hit can be a rule that EXCLUDES Citrix (a signer
allowlist) rather than one that detects it. For each result row the
list route attaches where the first `content:` term occurs in the rule
body, with a little context either side, and whether that term sits
only inside negated observables (NOT / exclusion lists), so a reader
can tell an allowlist from a detection without opening the rule.

Best-effort and cheap: pure string work over columns the row already
carries; no extra queries.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

# Characters of context kept either side of the match, and the fields
# searched in order (the logic first: shorter, and what the reader
# actually scans; the raw body catches metadata-only hits).
CONTEXT = 70
FIELDS = ("detection_logic", "raw_content")
_WS = re.compile(r"\s+")


def _flatten(text: str) -> str:
    return _WS.sub(" ", text)


def find_match(text: str, terms: Iterable[str]) -> Optional[tuple[int, int, str]]:
    """Earliest case-insensitive occurrence of any term: (start, end, term)."""
    if not text:
        return None
    lower = text.lower()
    best: Optional[tuple[int, int, str]] = None
    for term in terms:
        needle = (term or "").lower()
        if not needle:
            continue
        idx = lower.find(needle)
        if idx != -1 and (best is None or idx < best[0]):
            best = (idx, idx + len(needle), term)
    return best


def negated_hit(observables, term: str) -> bool:
    """True when `term` appears in the values of a negated observable
    and in no positive one. A term in both (detected here, excluded
    there) is not an exclusion-only hit; a term in neither is unknown
    and reported as a plain hit."""
    needle = (term or "").lower()
    if not needle:
        return False
    if isinstance(observables, dict):
        observables = observables.get("observables") or []
    negated = positive = False
    for obs in observables or []:
        if not isinstance(obs, dict):
            continue
        values = obs.get("values") or []
        if isinstance(values, str):
            values = [values]
        if not any(isinstance(v, str) and needle in v.lower() for v in values):
            continue
        if obs.get("negated"):
            negated = True
        else:
            positive = True
    return negated and not positive


def content_snippet(detection, terms: Iterable[str]) -> Optional[dict]:
    """The row-level snippet dict, or None when no term occurs in the body."""
    terms = [t for t in terms if t]
    if not terms:
        return None
    for field in FIELDS:
        text = getattr(detection, field, None) or ""
        found = find_match(text, terms)
        if found:
            break
    else:
        return None
    start, end, term = found
    before = _flatten(text[max(0, start - CONTEXT):start])
    after = _flatten(text[end:end + CONTEXT])
    if start - CONTEXT > 0:
        before = "..." + before.lstrip()
    if end + CONTEXT < len(text):
        after = after.rstrip() + "..."
    return {
        "term": term,
        "before": before,
        "match": text[start:end],
        "after": after,
        "field": field,
        "negated": negated_hit(getattr(detection, "extracted_observables", None), term),
    }
