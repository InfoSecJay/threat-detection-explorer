"""Rule-status vocabulary + building-block flag (issue #26).

Status follows Sigma 1:1 (stable / test / experimental / deprecated /
unsupported / unknown); building-block / signal-only is a separate
boolean, orthogonal to status. These tests pin the normalizer
vocabulary, the Elastic flag derivation, the query-bar `bool` kind and
the legacy-NULL tolerance of the response builders.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api.schemas import DetectionListItem, DetectionResponse
from app.normalizers.base import NormalizedDetection
from app.normalizers.elastic import ElasticNormalizer
from app.parsers.base import ParsedRule
from app.services.query_parser import QueryParseError, parse_query


@pytest.fixture
def elastic():
    return ElasticNormalizer("https://github.com/elastic/detection-rules")


# ── normalize_status vocabulary ───────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("stable", "stable"),
        ("production", "stable"),
        ("test", "test"),
        ("testing", "test"),
        ("experimental", "experimental"),
        ("development", "experimental"),
        ("deprecated", "deprecated"),
        ("unsupported", "unsupported"),
        ("Unsupported", "unsupported"),
        ("whatever", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_normalize_status_vocabulary(elastic, raw, expected):
    assert elastic.normalize_status(raw) == expected


# ── Elastic building-block derivation ─────────────────────────────────────


def _elastic_parsed(**overrides) -> ParsedRule:
    defaults = dict(
        source="elastic",
        file_path="rules/windows/credential_access_lsass.toml",
        raw_content="placeholder toml",
        title="LSASS access",
        detection_logic_raw={
            "type": "eql",
            "query": 'process where process.name == "lsass.exe"',
            "language": None,
        },
        description="d",
        author=["Elastic Security"],
        status="production",
        severity="high",
        log_source={"product": "windows"},
        tags=["Tactic: Credential Access"],
        mitre_attack={"tactics": ["TA0006"], "techniques": ["T1003.001"]},
        false_positives=[],
        extra={
            "rule_id": "f3c7c540-2a85-11ef-b88e-eb7e6d2b8e7c",
            "type": "eql",
            "language": None,
            "index": ["logs-endpoint.events.process-*"],
            "integration": ["endpoint"],
            "references": [],
            "creation_date": "2024/01/15",
            "updated_date": "2024/06/20",
            "promotion": False,
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


def test_elastic_regular_rule_is_not_a_building_block(elastic):
    n = elastic.normalize(_elastic_parsed())
    assert n.is_building_block is False
    assert n.status == "stable"


def test_elastic_building_block_type_sets_flag_and_keeps_status(elastic):
    extra = dict(_elastic_parsed().extra, building_block_type="default")
    n = elastic.normalize(_elastic_parsed(extra=extra))
    assert n.is_building_block is True
    assert n.status == "stable"  # orthogonal: a building block can be stable
    assert "building_block" in n.tags  # legacy tag kept for back-compat


def test_elastic_building_block_directory_sets_flag(elastic):
    n = elastic.normalize(
        _elastic_parsed(file_path="rules_building_block/windows/something.toml")
    )
    assert n.is_building_block is True


def test_normalized_detection_defaults_to_not_building_block():
    d = NormalizedDetection(
        id="x", source="sigma", source_file="f", source_repo_url="u",
        title="t", description=None, author=None, status="test", severity="low",
    )
    assert d.is_building_block is False
    assert d.status == "test"


# ── Query bar: bool kind ──────────────────────────────────────────────────


def _sql(clause) -> str:
    return str(clause.compile(compile_kwargs={"literal_binds": True})).lower()


def test_building_block_true_is_null_safe():
    sql = _sql(parse_query("building_block:true"))
    assert "is_building_block is" in sql and "is not" not in sql


def test_building_block_false_includes_null_rows():
    sql = _sql(parse_query("building_block:false"))
    assert "is_building_block is not" in sql


def test_building_block_aliases_and_negation():
    assert "is_building_block" in _sql(parse_query("bb:yes"))
    assert "is_building_block" in _sql(parse_query("signal_only:1"))
    assert "not" in _sql(parse_query("NOT building_block:true"))


def test_building_block_rejects_non_boolean():
    with pytest.raises(QueryParseError):
        parse_query("building_block:maybe")


def test_status_test_is_queryable():
    assert "status" in _sql(parse_query("status:test"))


# ── Response builders tolerate legacy NULL rows ──────────────────────────


def _row(**overrides):
    base = dict(
        id="d1", source="sigma", source_file="r.yml",
        source_repo_url="https://example.com/repo.git", source_rule_url=None,
        rule_id="r-1", title="Test Rule", description="d", author="a",
        status="test", severity="high",
        platforms=[], data_sources=[], event_types=[], use_cases=[],
        mitre_tactics=[], mitre_techniques=[], mitre_groups=[], mitre_software=[],
        detection_logic="x", language="sigma",
        tags=[], references=[], false_positives=[],
        extracted_fields_used=[], extracted_event_ids=[], extracted_process_names=[],
        extracted_file_paths=[], extracted_registry_keys=[],
        extracted_network_indicators=[], extracted_source_tables=[],
        extracted_observables=[], query_complexity="simple",
        extracted_api_actions=[], extracted_target_resources=[],
        rule_created_date=None, rule_modified_date=None,
        quality_score=None, quality_details=None, raw_content="raw",
        created_at=datetime(2026, 1, 1), updated_at=datetime(2026, 1, 1),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.parametrize("value, expected", [(None, False), (False, False), (True, True)])
def test_response_builders_coerce_building_block(value, expected):
    assert DetectionResponse.from_detection(_row(is_building_block=value)).is_building_block is expected
    assert DetectionListItem.from_detection(_row(is_building_block=value)).is_building_block is expected


def test_response_builders_survive_missing_column_attribute():
    # A row object from before the column existed at all.
    assert DetectionResponse.from_detection(_row()).is_building_block is False
    assert DetectionListItem.from_detection(_row()).status == "test"
