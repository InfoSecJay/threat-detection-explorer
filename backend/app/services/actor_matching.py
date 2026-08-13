"""Shared actor-name matching used by the actors API and score bundle.

The mention/exact matchers historically used `\\b<name>\\b` regexes and
raw `%name%` SQL LIKEs. Both silently miss how detection content
actually spells actor names:

- Splunk ESCU tags rules `story:salt_typhoon` — underscore-separated,
  and `\\b` can't anchor inside `salt_typhoon` because underscore is a
  word character. `\\bSalt Typhoon\\b` also never matches it because the
  alias has a space.
- References cite `.../salt-typhoon-analysis/` — hyphenated.
- Some content camel-cases (`SaltTyphoon`).

The fix is one canonical tokenization: an actor name is its alphanumeric
token sequence, and any run of separators (space, `_`, `-`, `.`, or
nothing at all) between tokens is equivalent. Boundaries are
"not adjacent to another alphanumeric" lookarounds, so underscores and
punctuation count as word breaks.

Everything here is pure string/regex logic so the routes and the score
bundle share identical semantics — divergence between the detail page
counts and the list page counts is exactly the bug class this module
exists to prevent.
"""

from __future__ import annotations

import re

# Alphanumeric runs — the canonical token stream of a name or label.
_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Separators tolerated between name tokens in free text. `*` (not `+`)
# so concatenated forms ("SaltTyphoon") match too.
_SEP = r"[\s_\-.]*"


def tokenize(name: str) -> list[str]:
    """Lowercase alphanumeric tokens of a name. "Salt Typhoon" -> ["salt", "typhoon"]."""
    return _TOKEN_RE.findall((name or "").lower())


def normalize_label(value: str) -> str:
    """Canonical form for equality checks: tokens joined by one space.

    "Salt Typhoon", "salt_typhoon", "SALT-TYPHOON" all normalize to
    "salt typhoon".
    """
    return " ".join(tokenize(value))


def compile_name_regex(names: list[str]) -> re.Pattern | None:
    """One case-insensitive regex matching ANY of `names` in free text.

    Per name: tokens joined by a flexible separator, anchored by
    not-alphanumeric lookarounds (NOT `\\b`, which treats `_` as a word
    character and misses `story:salt_typhoon`).
    """
    alts = []
    for name in names:
        tokens = tokenize(name)
        if not tokens:
            continue
        alts.append(_SEP.join(re.escape(t) for t in tokens))
    if not alts:
        return None
    return re.compile(
        r"(?<![a-z0-9])(" + "|".join(alts) + r")(?![a-z0-9])",
        re.IGNORECASE,
    )


def sql_like_patterns(name: str) -> list[str]:
    """Portable LIKE pre-filter patterns for one name.

    Two variants per name: tokens joined by `_` (the LIKE single-char
    wildcard, so one pattern covers space/underscore/hyphen/dot) and
    tokens concatenated (camel/squashed forms). Tokens are alphanumeric
    only, so no LIKE-metacharacter escaping is needed.

    The pre-filter is intentionally a superset of the regex — it only
    narrows the candidate set; compile_name_regex() is the authority.
    """
    tokens = tokenize(name)
    if not tokens:
        return []
    patterns = [f"%{'_'.join(tokens)}%"]
    if len(tokens) > 1:
        patterns.append(f"%{''.join(tokens)}%")
    return patterns


def label_like_patterns(name: str) -> list[str]:
    """LIKE patterns for a JSON-list column holding whole labels
    (e.g. use_cases): the quoted-element form of sql_like_patterns,
    so "Salt Typhoon" pre-filters `["Salt Typhoon"]` but a bare
    substring inside a longer label still gets rejected by the
    normalize_label equality check that follows.
    """
    tokens = tokenize(name)
    if not tokens:
        return []
    patterns = [f'%"{"_".join(tokens)}"%']
    if len(tokens) > 1:
        patterns.append(f'%"{"".join(tokens)}"%')
    return patterns


def labels_matching(labels: list, names: list[str]) -> bool:
    """True if any label in a JSON list equals any name after
    normalization — the "analytic story named after the actor" test.
    """
    wanted = {normalize_label(n) for n in names if n}
    wanted.discard("")
    for label in labels or []:
        if isinstance(label, str) and normalize_label(label) in wanted:
            return True
    return False
