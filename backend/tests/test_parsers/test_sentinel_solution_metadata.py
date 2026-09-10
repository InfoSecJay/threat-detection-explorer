"""#138: the parser reads Solutions/<vendor>/SolutionMetadata.json once
per clone root and attaches providers + normalized domains per rule."""

from __future__ import annotations

import json
from pathlib import Path

from app.parsers import sentinel as ps

RULE = """
id: 11111111-2222-3333-4444-555555555555
name: Cynerio - Device Compromised
description: test
severity: Medium
query: |
  CynerioEvent_CL | where Severity == "High"
"""


def _repo(tmp_path: Path, meta: dict) -> Path:
    root = tmp_path / "sentinel"
    sol = root / "Solutions" / "Cynerio"
    (sol / "Analytic Rules").mkdir(parents=True)
    (sol / "SolutionMetadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (sol / "Analytic Rules" / "rule.yaml").write_text(RULE, encoding="utf-8")
    return root


def test_metadata_is_attached_to_rules_of_that_solution(tmp_path):
    root = _repo(tmp_path, {
        "providers": ["Cynerio"],
        "categories": {"domains": ["Security - Vulnerability Management", "Security - Network"], "verticals": []},
    })
    parser = ps.SentinelParser()
    abs_path = root / "Solutions" / "Cynerio" / "Analytic Rules" / "rule.yaml"
    assert parser.can_parse(abs_path)
    parsed = parser.parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"), RULE)
    assert parsed.extra["solution_metadata"] == {
        "providers": ["Cynerio"],
        "domains": ["security - vulnerability management", "security - network"],
    }


def test_mojibake_dash_is_normalized(tmp_path):
    root = _repo(tmp_path, {"providers": ["X"], "categories": {"domains": ["Security \ufffd Network"]}})
    parser = ps.SentinelParser()
    parser.can_parse(root / "Solutions" / "Cynerio" / "Analytic Rules" / "rule.yaml")
    parsed = parser.parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"), RULE)
    assert parsed.extra["solution_metadata"]["domains"] == ["security - network"]


def test_relative_paths_and_missing_files_are_harmless(tmp_path):
    parser = ps.SentinelParser()
    parser.can_parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"))  # relative: no root
    parsed = parser.parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"), RULE)
    assert parsed.extra["solution_metadata"] == {}
    root = tmp_path / "bare"
    (root / "Solutions" / "Cynerio" / "Analytic Rules").mkdir(parents=True)
    parser.can_parse(root / "Solutions" / "Cynerio" / "Analytic Rules" / "rule.yaml")
    parsed = parser.parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"), RULE)
    assert parsed.extra["solution_metadata"] == {}


def test_malformed_metadata_does_not_stop_parsing(tmp_path):
    root = tmp_path / "sentinel"
    sol = root / "Solutions" / "Cynerio"
    (sol / "Analytic Rules").mkdir(parents=True)
    (sol / "SolutionMetadata.json").write_text("{not json", encoding="utf-8")
    parser = ps.SentinelParser()
    parser.can_parse(sol / "Analytic Rules" / "rule.yaml")
    parsed = parser.parse(Path("Solutions/Cynerio/Analytic Rules/rule.yaml"), RULE)
    assert parsed is not None and parsed.extra["solution_metadata"] == {}


def test_repo_root_detection():
    assert ps._repo_root_of("C:/x/repos/sentinel/Solutions/Acme/Analytic Rules/r.yaml") == "C:/x/repos/sentinel"
    assert ps._repo_root_of("/srv/repos/sentinel/Detections/Syslog/r.yaml") == "/srv/repos/sentinel"
    assert ps._repo_root_of("Solutions/Acme/Analytic Rules/r.yaml") == ""
