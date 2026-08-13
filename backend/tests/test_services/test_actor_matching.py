"""Tests for the shared actor-name matcher.

Pinned on the production bug that motivated the module: 60 Splunk ESCU
rules carry Salt Typhoon as `use_cases=["Salt Typhoon"]` and
`tags=["story:salt_typhoon"]`, but the old `\\b`-regex mention matcher
found only the 4 rules with the name in prose, and exact mode found 0
because ESCU never tags ATT&CK group IDs.
"""

from app.services.actor_matching import (
    compile_name_regex,
    label_like_patterns,
    labels_matching,
    normalize_label,
    sql_like_patterns,
    tokenize,
)


# ── Regex matching ─────────────────────────────────────────────────

def test_regex_matches_separator_variants():
    rx = compile_name_regex(["Salt Typhoon"])
    for text in (
        "Salt Typhoon activity",
        "story:salt_typhoon",
        "https://blog.example.com/salt-typhoon-analysis/",
        "SaltTyphoon implant",
        "SALT  TYPHOON",
        "salt.typhoon",
    ):
        assert rx.search(text), text


def test_regex_rejects_partial_token_hits():
    rx = compile_name_regex(["Salt Typhoon"])
    for text in (
        "basalt typhoon",       # 'salt' inside 'basalt'
        "salt typhoonish",      # trailing alnum continues the token
        "desalter typhoon",
        "typhoon salt",         # order matters
    ):
        assert not rx.search(text), text


def test_regex_underscore_is_a_boundary_not_a_word_char():
    # THE production case \b could not handle.
    rx = compile_name_regex(["Salt Typhoon"])
    assert rx.search("prefix_salt_typhoon_suffix")


def test_regex_multiple_names_or_together():
    rx = compile_name_regex(["Salt Typhoon", "GhostEmperor"])
    assert rx.search("attributed to ghostemperor operators")
    assert rx.search("story:salt_typhoon")
    assert not rx.search("ghost of the emperor")  # camel name stays one token


def test_regex_none_for_empty_names():
    assert compile_name_regex([]) is None
    assert compile_name_regex(["___"]) is None


# ── Normalization / label equality ─────────────────────────────────

def test_normalize_label_collapses_separators_and_case():
    assert normalize_label("Salt Typhoon") == "salt typhoon"
    assert normalize_label("salt_typhoon") == "salt typhoon"
    assert normalize_label("SALT-TYPHOON") == "salt typhoon"
    assert normalize_label("  Salt   Typhoon  ") == "salt typhoon"


def test_labels_matching_is_whole_label_equality():
    names = ["Salt Typhoon", "GhostEmperor"]
    assert labels_matching(["Salt Typhoon"], names)
    assert labels_matching(["salt_typhoon"], names)
    assert labels_matching(["Ransomware", "GhostEmperor"], names)
    # Longer labels merely CONTAINING the name are mentions, not tags.
    assert not labels_matching(["Salt Typhoon Campaign 2025"], names)
    assert not labels_matching([], names)
    assert not labels_matching([None, 42], names)  # non-strings ignored


# ── SQL pre-filter patterns ────────────────────────────────────────

def test_sql_like_patterns_cover_separator_and_squashed_forms():
    # `_` is the LIKE single-char wildcard: one pattern covers
    # space/underscore/hyphen/dot separators.
    assert sql_like_patterns("Salt Typhoon") == [
        "%salt_typhoon%",
        "%salttyphoon%",
    ]
    # Single-token names need no squashed variant.
    assert sql_like_patterns("GhostEmperor") == ["%ghostemperor%"]
    assert sql_like_patterns("!!!") == []


def test_label_like_patterns_pin_label_boundaries_with_quotes():
    assert label_like_patterns("Salt Typhoon") == [
        '%"salt_typhoon"%',
        '%"salttyphoon"%',
    ]


def test_tokenize():
    assert tokenize("Salt Typhoon") == ["salt", "typhoon"]
    assert tokenize("APT29") == ["apt29"]
    assert tokenize("") == []
