"""What counts as technique coverage (DX-05 / #147): one rule, shared by
the actor bundle (Python twin) and the matrix/heatmap scans (SQL)."""

from app.services.coverage_scope import counts_as_coverage, coverage_conditions
from app.services.taxonomy.canonical import COVERAGE_EXCLUDED_MODALITIES, RULE_MODALITIES


def test_excluded_modalities_are_real_modalities_and_rule_is_not_one():
    assert COVERAGE_EXCLUDED_MODALITIES <= RULE_MODALITIES
    assert "rule" not in COVERAGE_EXCLUDED_MODALITIES
    assert {"hunting", "building_block", "passthrough", "indicator_match"} == COVERAGE_EXCLUDED_MODALITIES


def test_counts_as_coverage_python_twin():
    assert counts_as_coverage("stable", "rule")
    assert counts_as_coverage("stable", None)  # legacy rows default to rule
    assert counts_as_coverage("stable", "correlation")  # alert-on-alert still detects
    assert counts_as_coverage("stable", "ml_job")
    for m in COVERAGE_EXCLUDED_MODALITIES:
        assert not counts_as_coverage("stable", m), m
    assert not counts_as_coverage("deprecated", "rule")


def test_coverage_conditions_render_both_clauses():
    rendered = " ".join(str(c) for c in coverage_conditions())
    assert "detections.status !=" in rendered
    assert "detections.rule_modality" in rendered and "NOT IN" in rendered
