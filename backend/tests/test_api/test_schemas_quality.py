"""Regression: legacy quality_details values must not 500 serialization.

Production rows from pre-#10 ingests carry `[]` in quality_details
(and could carry junk in quality_score). DetectionResponse coerces
non-dict/non-int to None instead of raising ValidationError — the
2026-08-28 detail-page outage class.
"""

from types import SimpleNamespace
from datetime import datetime

from app.api.schemas import DetectionListItem, DetectionResponse


def _detection(**overrides):
    base = dict(
        id="d1",
        source="sigma",
        source_file="r.yml",
        source_repo_url="https://example.com/repo.git",
        source_rule_url=None,
        rule_id="r-1",
        title="Test Rule",
        description="d",
        author="a",
        status="stable",
        severity="high",
        platforms=[], data_sources=[], event_types=[], use_cases=[],
        mitre_tactics=[], mitre_techniques=[], mitre_groups=[],
        mitre_software=[],
        detection_logic="x",
        language="sigma",
        tags=[], references=[], false_positives=[],
        extracted_fields_used=[], extracted_event_ids=[],
        extracted_process_names=[], extracted_file_paths=[],
        extracted_registry_keys=[], extracted_network_indicators=[],
        extracted_source_tables=[], extracted_observables=[],
        query_complexity="simple",
        extracted_api_actions=[], extracted_target_resources=[],
        rule_created_date=None, rule_modified_date=None,
        quality_score=None, quality_details=None,
        raw_content="raw",
        created_at=datetime(2026, 1, 1),
        updated_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_legacy_empty_list_quality_details_serializes():
    d = _detection(quality_details=[], quality_score=None)
    resp = DetectionResponse.from_detection(d)
    assert resp.quality_details is None
    item = DetectionListItem.from_detection(d)
    assert item.quality_score is None


def test_junk_quality_score_coerced():
    d = _detection(quality_score="62", quality_details={"total": 62})
    resp = DetectionResponse.from_detection(d)
    assert resp.quality_score is None  # strings are junk, not scores
    assert resp.quality_details == {"total": 62}


def test_real_quality_values_pass_through():
    details = {"version": 1, "total": 71, "dimensions": {}}
    d = _detection(quality_score=71, quality_details=details)
    resp = DetectionResponse.from_detection(d)
    assert resp.quality_score == 71
    assert resp.quality_details == details
