"""Tests for the deterministic metadata-completeness scorer (issue #10, rubric v2 per teardown F09)."""

from datetime import datetime

from app.normalizers.base import NormalizedDetection
from app.services.quality_score import RUBRIC_VERSION, score_detection


def _rule(**overrides) -> NormalizedDetection:
    defaults = dict(
        id="t1",
        source="sigma",
        source_file="r.yml",
        source_repo_url="https://example.com/repo.git",
        title="Suspicious PowerShell Encoded Command Execution",
        description=(
            "Detects PowerShell launched with an encoded command, a common "
            "obfuscation wrapper for droppers and loaders. Investigate the "
            "decoded script block and correlate with parent process lineage "
            "before escalating; build a baseline of admin automation first."
        ),
        author="Test Author",
        rule_id="abc-123",
        status="stable",
        severity="high",
        mitre_tactics=["TA0002"],
        mitre_techniques=["T1059.001", "T1027"],
        mitre_groups=[],
        mitre_software=[],
        detection_logic="x",
        language="sigma",
        tags=["attack.execution"],
        references=[
            "https://redcanary.com/blog/powershell-abuse/",
            "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md",
        ],
        false_positives=[
            "Administrative automation frameworks that wrap scripts in "
            "encoded commands; verify the signer and the schedule.",
        ],
        raw_content="title: x",
        extracted_fields_used=[
            "Image", "CommandLine", "ParentImage", "OriginalFileName",
            "User", "IntegrityLevel", "Hashes", "CurrentDirectory",
        ],
        query_complexity="moderate",
        rule_created_date=datetime(2024, 1, 1),
    )
    defaults.update(overrides)
    return NormalizedDetection(**defaults)


def test_well_hygiened_rule_scores_high():
    total, details = score_detection(_rule())
    assert details["version"] == RUBRIC_VERSION
    assert total == details["total"]
    assert total >= 80
    assert set(details["dimensions"]) == {
        "metadata", "mitre", "specificity", "documentation", "testability",
    }
    for d in details["dimensions"].values():
        assert 0 <= d["score"] <= d["of"] <= 20


def test_sublime_scored_only_on_expressible_checks():
    # MQL cannot carry ATT&CK tags, an author field, or a
    # false-positive field, and Atomic Red Team has no email atomics:
    # none of those may count against a Sublime rule (teardown F09).
    total, details = score_detection(_rule(
        source="sublime",
        author=None,
        mitre_tactics=[],
        mitre_techniques=[],
        false_positives=[],
        references=["https://redcanary.com/blog/phishing/"],
    ))
    assert "mitre" not in details["dimensions"]
    meta = details["dimensions"]["metadata"]
    assert meta["of"] == 17 and "no author" not in meta["issues"] and "no author" in meta["na"]
    doc = details["dimensions"]["documentation"]
    assert doc["of"] == 12 and "no false-positive analysis" not in doc["issues"]
    testability = details["dimensions"]["testability"]
    assert testability["of"] == 9  # intel 6 + emulation 3
    assert "no Atomic Red Team reference" not in testability["issues"]
    assert details["applicable_points"] == 17 + 20 + 12 + 9
    assert total == round(100 * details["raw"] / details["applicable_points"])
    # A well-documented Sublime rule must be able to score high.
    assert total >= 75


def test_sentinel_not_docked_for_missing_fp_and_reference_fields():
    total, details = score_detection(_rule(source="sentinel", references=[], false_positives=[]))
    doc = details["dimensions"]["documentation"]
    assert "no false-positive analysis" not in doc["issues"]
    meta = details["dimensions"]["metadata"]
    assert "no references" not in meta["issues"]
    testability = details["dimensions"]["testability"]
    assert "no threat-research reference" not in testability["issues"]
    assert details["applicable_points"] < 100


def test_default_profile_still_scores_over_the_full_rubric_minus_embedded():
    # Sigma has no embedded-test convention; everything else applies.
    _total, details = score_detection(_rule(source="sigma"))
    assert details["applicable_points"] == 97
    assert set(details["dimensions"]) == {
        "metadata", "mitre", "specificity", "documentation", "testability",
    }


def test_bare_rule_scores_low_with_issues():
    total, details = score_detection(_rule(
        title="Rule",
        description=None,
        author=None,
        rule_id=None,
        references=[],
        false_positives=[],
        mitre_tactics=[],
        mitre_techniques=[],
        extracted_fields_used=[],
        query_complexity="unknown",
        rule_created_date=None,
    ))
    assert total <= 10
    assert "no ATT&CK technique mapping" in details["dimensions"]["mitre"]["issues"]
    assert "no false-positive analysis" in details["dimensions"]["documentation"]["issues"]
    assert "no telemetry fields extracted" in details["dimensions"]["specificity"]["issues"]


def test_boilerplate_false_positives_score_below_concrete():
    concrete = score_detection(_rule())[1]["dimensions"]["documentation"]["score"]
    boiler = score_detection(
        _rule(false_positives=["Unknown", "Legitimate admin activity"])
    )[1]
    assert boiler["dimensions"]["documentation"]["score"] < concrete
    assert (
        "false positives are boilerplate, not analysis"
        in boiler["dimensions"]["documentation"]["issues"]
    )


def test_atomic_reference_drives_testability():
    with_atomic = score_detection(_rule())[1]["dimensions"]["testability"]["score"]
    without = score_detection(_rule(references=["https://example.com/docs"]))[1]
    assert with_atomic > without["dimensions"]["testability"]["score"]
    assert (
        "no Atomic Red Team reference"
        in without["dimensions"]["testability"]["issues"]
    )


def test_subtechnique_precision_beats_bare_technique():
    precise = score_detection(_rule())[1]["dimensions"]["mitre"]["score"]
    bare = score_detection(_rule(mitre_techniques=["T1059"]))[1]["dimensions"]["mitre"]["score"]
    assert precise > bare


def test_deterministic():
    a = score_detection(_rule())
    b = score_detection(_rule())
    assert a == b


def test_complexity_ladder():
    def spec(c):
        return score_detection(_rule(query_complexity=c))[1]["dimensions"]["specificity"]["score"]
    assert spec("simple") < spec("moderate") < spec("complex")


def test_panther_tests_block_earns_embedded_tests_credit():
    """Rubric v3: panther YAML carries `Tests:` blocks with log-event
    samples (871/877 upstream rules), so the embedded_tests check
    applies and is earned when the block is present."""
    yaml_with_tests = (
        "AnalysisType: rule\nRuleID: X.Y\n"
        "Tests:\n"
        "  - Name: benign login\n"
        "    ExpectedResult: false\n"
        "    Log: {\"eventName\": \"ConsoleLogin\"}\n"
    )
    _, with_tests = score_detection(
        _rule(source="panther", raw_content=yaml_with_tests)
    )
    _, without = score_detection(
        _rule(source="panther", raw_content="AnalysisType: rule\nRuleID: X.Y\n")
    )
    t_with = with_tests["dimensions"]["testability"]
    t_without = without["dimensions"]["testability"]
    assert t_with["score"] == t_without["score"] + 3
    assert "no embedded test cases" not in t_with["issues"]
