"""rule_modality (#105 / teardown R06-R07, B7-B8).

How a rule works used to leak into two unrelated facets: `event_type`
carried hunting_query / ml_detection / alert_correlation and
`language` carried ml / threat_match / panther_correlation. Both now
live on `rule_modality`; `event_types` holds only observed-event
categories and `language` only query languages.
"""

from __future__ import annotations

import pytest

from app.normalizers.base import NormalizedDetection
from app.normalizers.elastic import ElasticNormalizer
from app.parsers.base import ParsedRule
from app.services.taxonomy.canonical import EVENT_TYPE_MODALITY_LIFT, EVENT_TYPES, RULE_MODALITIES


def _norm(**overrides) -> NormalizedDetection:
    base = dict(
        id="x", source="sigma", source_file="r.yml", source_repo_url="https://x",
        title="t", description=None, author=None, status="test", severity="low",
        platforms=["windows"], data_sources=["sysmon"], event_types=["process_creation"],
    )
    base.update(overrides)
    return NormalizedDetection(**base)


# ── the lift in __post_init__ ─────────────────────────────────────────


def test_markers_are_canonical_event_types_but_never_stored():
    # They must stay accepted by the mapping validator...
    assert set(EVENT_TYPE_MODALITY_LIFT) <= EVENT_TYPES
    # ...and every lift target must be a real modality.
    assert set(EVENT_TYPE_MODALITY_LIFT.values()) <= RULE_MODALITIES


@pytest.mark.parametrize("marker, modality", sorted(EVENT_TYPE_MODALITY_LIFT.items()))
def test_marker_is_lifted_off_event_types(marker, modality):
    n = _norm(event_types=[marker, "process_creation"])
    assert n.rule_modality == modality
    assert n.event_types == ["process_creation"]


def test_marker_only_rule_becomes_unknown_event_type_not_empty():
    n = _norm(event_types=["ml_detection"])
    assert n.rule_modality == "ml_job"
    assert n.event_types == ["unknown"]


def test_explicit_modality_beats_the_marker():
    n = _norm(rule_modality="correlation", event_types=["hunting_query"])
    assert n.rule_modality == "correlation"
    assert "hunting_query" not in n.event_types


def test_building_block_fills_the_default_only():
    assert _norm(is_building_block=True).rule_modality == "building_block"
    assert _norm(is_building_block=True, rule_modality="hunting").rule_modality == "hunting"
    assert _norm(is_building_block=True, event_types=["ml_detection"]).rule_modality == "ml_job"


def test_unknown_vocabulary_falls_back_to_rule():
    assert _norm(rule_modality="anomaly").rule_modality == "rule"


# ── Elastic: vendor rule type -> modality, language cleaned ───────────


@pytest.fixture
def elastic():
    return ElasticNormalizer("https://github.com/elastic/detection-rules")


def _elastic_rule(rule_type: str, **logic) -> ParsedRule:
    return ParsedRule(
        source="elastic", file_path="rules/windows/x.toml", raw_content="toml", title="t",
        detection_logic_raw={"type": rule_type, **logic}, description=None, author=None,
        status="production", severity="high", log_source={"product": "windows"}, tags=[],
        mitre_attack={"tactics": [], "techniques": []}, false_positives=[],
        extra={"type": rule_type, "index": ["logs-endpoint.events.*"], "integration": ["endpoint"], "promotion": False, **logic},
    )


def test_elastic_ml_rule_has_no_language_and_ml_modality(elastic):
    n = elastic.normalize(_elastic_rule("machine_learning", query="", language=None))
    assert n.rule_modality == "ml_job"
    assert n.language == "none"


def test_elastic_threat_match_keeps_its_query_language(elastic):
    n = elastic.normalize(_elastic_rule("threat_match", query="destination.ip:*", language="kuery"))
    assert n.rule_modality == "indicator_match"
    assert n.language == "kql"


def test_elastic_plain_query_is_a_rule(elastic):
    n = elastic.normalize(_elastic_rule("eql", query='process where true'))
    assert n.rule_modality == "rule"
    assert n.language == "eql"
