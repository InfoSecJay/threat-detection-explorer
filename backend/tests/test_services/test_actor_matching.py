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


# == Case-sensitive all-caps codenames (issue #33) ==================
#
# APT41's alias "LEAD" matched every rule description containing the
# English verb "lead" -- 197 of its 200 mention hits. All-caps
# single-token alphabetic codenames must match with exact casing.

from app.services.actor_matching import is_case_sensitive_name


def test_is_case_sensitive_name_classification():
    # The hazard class: single-token, purely alphabetic, all-caps.
    assert is_case_sensitive_name("LEAD")
    assert is_case_sensitive_name("BARIUM")
    assert is_case_sensitive_name("BLINDINGCAN")
    # Digits make a name distinctive -- stays case-insensitive.
    assert not is_case_sensitive_name("APT41")
    assert not is_case_sensitive_name("TA415")
    # Multi-token all-caps is distinctive as a sequence.
    assert not is_case_sensitive_name("WICKED SPIDER")
    # Mixed/title case is not the hazard class.
    assert not is_case_sensitive_name("Winnti")
    assert not is_case_sensitive_name("GhostEmperor")


def test_allcaps_codename_does_not_match_english_prose():
    rx = compile_name_regex(["LEAD"])
    for text in (
        "activity that may lead to unauthorized access",
        "Leads to remote code execution",
        "Lead engineer approval required",
        "misleading indicators",
    ):
        assert not rx.search(text), text


def test_allcaps_codename_matches_exact_case_usage():
    rx = compile_name_regex(["LEAD"])
    for text in (
        "attributed to LEAD operators",
        "LEAD (also tracked as BARIUM)",
        "story:LEAD",
    ):
        assert rx.search(text), text


def test_mixed_name_list_keeps_insensitive_semantics_for_safe_names():
    # One regex holding both classes: APT41 stays case-insensitive
    # (lowercase URLs must still count), LEAD goes exact-case.
    rx = compile_name_regex(["APT41", "Wicked Panda", "LEAD"])
    assert rx.search("https://example.com/apt41-dual-espionage-report/")
    assert rx.search("wicked_panda staging")
    assert rx.search("WICKED-PANDA infra")
    assert not rx.search("this may lead to data loss")
    assert rx.search("overlaps with LEAD tooling")
