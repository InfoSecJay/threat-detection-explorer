"""Derived ATT&CK mapping from Sublime attack_types (teardown R10 / #108).

Sublime publishes a 7-value email-threat classification instead of
ATT&CK ids. The parser translates it when (and only when) the rule
declares no technique of its own, and tags the provenance.
"""

from pathlib import Path

import pytest

from app.parsers.sublime import SublimeParser


def _rule_yaml(attack_types: list[str], tnt: list[str] | None = None) -> str:
    at = "".join(f'\n  - "{a}"' for a in attack_types)
    tt = "".join(f'\n  - "{t}"' for t in (tnt or []))
    return (
        'name: "Test rule"\n'
        'description: "d"\n'
        'severity: high\n'
        'source: |\n'
        '  type.inbound\n'
        f"attack_types:{at or ' []'}\n"
        f"tactics_and_techniques:{tt or ' []'}\n"
    )


@pytest.fixture
def parser():
    return SublimeParser()


def _parse(parser, yaml_text):
    return parser.parse(Path("detection-rules/test.yml"), yaml_text)


def test_credential_phishing_maps_to_spearphishing_link(parser):
    r = _parse(parser, _rule_yaml(["Credential Phishing"], ["Social engineering"]))
    assert r.mitre_attack["techniques"] == ["T1566.002"]
    assert "TA0001" in r.mitre_attack["tactics"]
    assert "mitre-mapping:derived" in r.tags


def test_attachment_signal_refines_to_spearphishing_attachment(parser):
    r = _parse(parser, _rule_yaml(["Credential Phishing"], ["PDF", "Social engineering"]))
    assert r.mitre_attack["techniques"] == ["T1566.001"]


def test_full_vocabulary_maps(parser):
    r = _parse(
        parser,
        _rule_yaml(["Malware/Ransomware", "BEC/Fraud", "Callback Phishing", "Extortion"]),
    )
    assert r.mitre_attack["techniques"] == ["T1204.002", "T1656", "T1566.004", "T1657"]
    assert set(r.mitre_attack["tactics"]) == {"TA0002", "TA0005", "TA0001", "TA0040"}


def test_spam_only_maps_nothing(parser):
    r = _parse(parser, _rule_yaml(["Spam"]))
    assert r.mitre_attack["techniques"] == []
    assert "mitre-mapping:derived" not in r.tags


def test_vendor_declared_techniques_are_never_overridden(parser):
    yaml_text = _rule_yaml(["Credential Phishing"]).replace(
        "tactics_and_techniques: []",
        'tactics_and_techniques:\n  - "T1078"',
    )
    r = _parse(parser, yaml_text)
    assert r.mitre_attack["techniques"] == ["T1078"]
    assert "mitre-mapping:derived" not in r.tags
