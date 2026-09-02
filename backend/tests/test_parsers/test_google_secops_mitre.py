"""ATT&CK extraction from Google SecOps (Chronicle) YARA-L meta (#108 C6).

The community repo mixes two conventions: the id-based `tactic` /
`technique` pair, and the older display-name set (`mitre_attack_tactic`,
`mitre_attack_technique`, `mitre_attack_url`). Before this the parser
only read the URL form, so 234 of 379 rules carried no technique.
"""

from pathlib import Path

import pytest

from app.parsers.google_secops import GoogleSecOpsParser


def _rule(meta_lines: list[str]) -> str:
    meta = "\n".join(f"    {line}" for line in meta_lines)
    return (
        "rule test_rule {\n"
        "  meta:\n"
        '    author = "tester"\n'
        '    description = "d"\n'
        '    severity = "Medium"\n'
        f"{meta}\n"
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )


@pytest.fixture
def parser():
    return GoogleSecOpsParser()


def _parse(parser, text):
    return parser.parse(Path("rules/community/test/test_rule.yaral"), text)


def test_id_based_tactic_and_technique_fields(parser):
    r = _parse(parser, _rule(['tactic = "TA0006"', 'technique = "T1003.001"']))
    assert r.mitre_attack["techniques"] == ["T1003.001"]
    assert r.mitre_attack["tactics"] == ["TA0006"]
    # The tactic id is ATT&CK data, not a free-form tag.
    assert "ta0006" not in r.tags


def test_display_name_tactics_split_on_comma(parser):
    r = _parse(parser, _rule([
        'mitre_attack_tactic = "Defense Evasion, Persistence, Privilege Escalation, Initial Access"',
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1078/004/"',
    ]))
    assert r.mitre_attack["tactics"] == ["TA0005", "TA0003", "TA0004", "TA0001"]
    assert r.mitre_attack["techniques"] == ["T1078.004"]


def test_display_name_technique_resolves_when_no_id_present(parser):
    r = _parse(parser, _rule([
        'mitre_attack_tactic = "Credential Access"',
        'mitre_attack_technique = "OS Credential Dumping: LSASS Memory"',
        'mitre_attack_url = ""',
    ]))
    assert r.mitre_attack["techniques"] == ["T1003.001"]


def test_parent_display_name_resolves(parser):
    r = _parse(parser, _rule(['mitre_attack_technique = "Valid Accounts"']))
    assert r.mitre_attack["techniques"] == ["T1078"]


def test_display_name_never_shadows_an_id(parser):
    # Name says parent, URL says sub-technique: the id wins outright.
    r = _parse(parser, _rule([
        'mitre_attack_technique = "OS Credential Dumping"',
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1003/001/"',
    ]))
    assert r.mitre_attack["techniques"] == ["T1003.001"]


def test_tactics_inferred_from_techniques_when_meta_has_none(parser):
    r = _parse(parser, _rule(['technique = "T1003.001"']))
    assert r.mitre_attack["tactics"] == ["TA0006"]


def test_unknown_display_name_yields_nothing(parser):
    r = _parse(parser, _rule(['mitre_attack_technique = "Not A Real Technique"']))
    assert r.mitre_attack["techniques"] == []
    assert r.mitre_attack["tactics"] == []


def test_empty_meta_values_are_harmless(parser):
    r = _parse(parser, _rule([
        'mitre_attack_tactic = "Persistence"',
        'mitre_attack_technique = ""',
        'mitre_attack_url = ""',
    ]))
    assert r.mitre_attack["tactics"] == ["TA0003"]
    assert r.mitre_attack["techniques"] == []
