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

# Strict boundaries for AMBIGUOUS_TOKENS names: reject `.`/`-`/`_`
# adjacency outright, so `linux.die.net` / `Pwnage.ps1` /
# `hermetic_wiper` can't glue a common word onto a neighboring token.
_STRICT_L = r"(?<![._\-])"
_STRICT_R = r"(?![._\-])"


def tokenize(name: str) -> list[str]:
    """Lowercase alphanumeric tokens of a name. "Salt Typhoon" -> ["salt", "typhoon"]."""
    return _TOKEN_RE.findall((name or "").lower())


def normalize_label(value: str) -> str:
    """Canonical form for equality checks: tokens joined by one space.

    "Salt Typhoon", "salt_typhoon", "SALT-TYPHOON" all normalize to
    "salt typhoon".
    """
    return " ".join(tokenize(value))


# Single-token software names that are ordinary words, OS-utility
# names, or file-extension lookalikes (issue #35). The separator-
# tolerant matcher exists so "Salt Typhoon" hits `story:salt_typhoon`,
# but for these names the same tolerance is the dominant FP source:
# S0039 "Net" matched the `.net` TLD in every reference URL
# (`linux.die.net`) and ".NET framework" prose; S0613 "PS1" (a Turla
# backdoor) matched every `.ps1` script path; S0041 "Wiper" (a
# specific 2013 malware) absorbed OTHER wipers' compound names
# (`hermetic_wiper`); S0103 "route" matched AWS `route_53` tags.
# Curated from the issue #35 corpus audit — extend it when a new
# catalog entry shows the same hazard, and keep names like QakBot out:
# distinctive single tokens NEED separator glue to hit URL slugs
# (`/qbot-and-zerologon-...`).
AMBIGUOUS_TOKENS = frozenset({
    "net", "cmd", "ping", "route", "ps1", "wiper",
})

# Aliases that are unmatchable in free text at ANY boundary strictness:
# ordinary prose words with no casing or separator signal to exploit.
# S0081 Elise's alias "Page" produced 72 of its 74 mention hits from
# "Outlook Home Page" / "code page" / "?page=" prose (issue #35 audit)
# — strict boundaries can't help a word that legitimately stands alone.
# Dropped from regex matching entirely; still honored by
# labels_matching(), where whole-label equality keeps FP risk low.
UNMATCHABLE_TOKENS = frozenset({
    "page",
})


def is_unmatchable_name(name: str) -> bool:
    """Names skipped by compile_name_regex — see UNMATCHABLE_TOKENS."""
    tokens = tokenize(name)
    return len(tokens) == 1 and tokens[0] in UNMATCHABLE_TOKENS


def is_ambiguous_name(name: str) -> bool:
    """Single-token names that collide with English words, URLs, or
    file extensions — matched standalone only (issue #35).

    These names must not be glued to a neighboring token by `.`, `-`,
    or `_`: "net use" and "Ping Hex IP" still match, `linux.die.net`,
    `Pwnage.ps1`, and `hermetic_wiper` no longer do. Distinctive
    aliases of the same entity ("net.exe", "cmd.exe") are multi-token
    and keep the flexible-separator semantics. Accepted FP remainder:
    standalone prose usage ("a route table", "BiBi wiper") survives —
    killing it needs semantics, not boundaries.
    """
    tokens = tokenize(name)
    return len(tokens) == 1 and tokens[0] in AMBIGUOUS_TOKENS


def is_case_sensitive_name(name: str) -> bool:
    """Names that must match with their exact casing.

    Single-token, purely-alphabetic, ALL-CAPS vendor codenames (LEAD,
    BARIUM, BLINDINGCAN) collide with English prose when matched
    case-insensitively — APT41's alias "LEAD" matched every rule whose
    description said "may lead to ...", 197 of its 200 mention hits
    (issue #33). Intel and rule text write these codenames all-caps,
    prose doesn't, so exact-case matching removes the FP class.

    Multi-token names ("WICKED SPIDER") and names carrying digits
    ("APT41", "TA415") are distinctive even lowercased (reference URLs
    lowercase everything) and stay case-insensitive. Accepted FN: an
    all-caps codename written in lowercase prose no longer counts.
    """
    return name.isupper() and name.isalpha()


def compile_name_regex(names: list[str]) -> re.Pattern | None:
    """One regex matching ANY of `names` in free text.

    Per name: tokens joined by a flexible separator, anchored by
    not-alphanumeric lookarounds (NOT `\\b`, which treats `_` as a word
    character and misses `story:salt_typhoon`). Most names match
    case-insensitively via a scoped `(?i:...)` group; names flagged by
    is_case_sensitive_name() must appear with their exact casing.
    """
    insensitive = []
    sensitive = []
    for name in names:
        tokens = tokenize(name)
        if not tokens or is_unmatchable_name(name):
            continue
        if is_case_sensitive_name(name):
            # Preserve the original casing — tokenize() lowercases, and
            # an all-caps alphabetic name is a single token anyway.
            body = re.escape(name)
            if is_ambiguous_name(name):
                body = _STRICT_L + body + _STRICT_R
            sensitive.append(body)
        elif is_ambiguous_name(name):
            # Standalone-word only: no `.`/`-`/`_` glue to a neighbor
            # token (issue #35) — the outer lookarounds already reject
            # adjacent alphanumerics.
            insensitive.append(_STRICT_L + re.escape(tokens[0]) + _STRICT_R)
        else:
            insensitive.append(_SEP.join(re.escape(t) for t in tokens))
    alts = []
    if insensitive:
        alts.append(r"(?i:" + "|".join(insensitive) + r")")
    alts.extend(sensitive)
    if not alts:
        return None
    return re.compile(
        r"(?<![A-Za-z0-9])(" + "|".join(alts) + r")(?![A-Za-z0-9])"
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
