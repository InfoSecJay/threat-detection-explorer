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


# ── DX-05 / #147: passthrough and indicator-only lifts ────────────────


def test_platform_alert_event_type_lifts_to_passthrough_and_stays_on_event_types():
    n = _norm(event_types=["platform_alert"])
    assert n.rule_modality == "passthrough"
    # Unlike the marker lifts, the event type is real: the rule reads alerts.
    assert n.event_types == ["platform_alert"]


def test_siem_alert_catch_all_alone_is_not_a_passthrough():
    """`siem_alert` is also the domain-less catch-all for unlisted Sentinel
    tables (#138, about half of Sentinel): on its own it says nothing."""
    n = _norm(data_sources=["siem_alert"], event_types=["audit_event"])
    assert n.rule_modality == "rule"
    n = _norm(data_sources=["siem_alert"], event_types=["audit_event"], extracted_source_tables=["SomeVendor_CL"])
    assert n.rule_modality == "rule"


def test_catch_all_plus_an_alert_named_table_is_a_passthrough():
    """The review's two Sentinel examples: vendor alert tables the mapping
    does not list, so the only evidence is the table name."""
    for table in ("TrendAI_XDR_WORKBENCH_V2_CL", "GoogleSecOpsDetectionAlerts", "SecurityAlert", "Vendor_Findings_CL"):
        n = _norm(data_sources=["siem_alert"], event_types=["audit_event"], extracted_source_tables=[table])
        assert n.rule_modality == "passthrough", table
        assert n.event_types == ["audit_event"]  # what it reads is untouched


def test_alert_named_table_needs_the_catch_all():
    # A listed telemetry source is trusted over a coincidental table name.
    n = _norm(data_sources=["sysmon"], event_types=["process_creation"], extracted_source_tables=["SecurityAlert"])
    assert n.rule_modality == "rule"


def test_only_the_primary_table_counts():
    """Measured on the clone: 'Azure DevOps Pipeline modified by a new
    user' reads ADOAuditLogs and joins SecurityAlert for enrichment.
    The statement head (first table, #141) is what the rule detects on."""
    n = _norm(data_sources=["siem_alert"], event_types=["audit_event"], extracted_source_tables=["ADOAuditLogs", "SecurityAlert"])
    assert n.rule_modality == "rule"
    n = _norm(data_sources=["siem_alert"], event_types=["audit_event"], extracted_source_tables=["SecurityAlert", "ADOAuditLogs"])
    assert n.rule_modality == "passthrough"


def test_explicit_modality_beats_the_passthrough_lift():
    assert _norm(rule_modality="correlation", event_types=["platform_alert"]).rule_modality == "correlation"
    assert _norm(is_building_block=True, event_types=["platform_alert"]).rule_modality == "building_block"


def _obs(subtype, values, otype="file", negated=False):
    return {"field": "f", "values": values, "type": otype, "subtype": subtype, "negated": negated}


def test_indicator_only_observables_lift_to_indicator_match():
    n = _norm(extracted_observables=[_obs("file_hash", ["a" * 64]), _obs("ip_address", ["10.0.0.1"], "network")])
    assert n.rule_modality == "indicator_match"


def test_a_behavioural_observable_keeps_the_rule_a_rule():
    n = _norm(extracted_observables=[_obs("file_hash", ["a" * 64]), _obs("process_name", ["mimikatz.exe"], "process")])
    assert n.rule_modality == "rule"


def test_negated_indicators_alone_are_not_an_indicator_list():
    # An allowlist of hashes is an exclusion, not what the rule detects.
    n = _norm(extracted_observables=[_obs("file_hash", ["a" * 64], negated=True)])
    assert n.rule_modality == "rule"
    assert _norm(extracted_observables=[]).rule_modality == "rule"


def test_indicator_lift_needs_literal_values_not_field_references():
    """Measured on the clones: 'Internal Horizontal Port Scan' keys on
    src_ip=* (typed ip_address) and 'Apache - Command in URI' on a url
    pattern -- behaviour, not an IOC list. Only literal hashes / IPs lift."""
    assert _norm(extracted_observables=[_obs("ip_address", ["*"], "network")]).rule_modality == "rule"
    assert _norm(extracted_observables=[_obs("ip_address", ["src_ip"], "network")]).rule_modality == "rule"
    assert _norm(extracted_observables=[_obs("url", ["/etc/passwd"], "network")]).rule_modality == "rule"
    assert _norm(extracted_observables=[_obs("domain", ["evil.example"], "network")]).rule_modality == "rule"
    # A CIDR is a scope (the port-scan rules filter to 10.0.0.0/8), not an indicator.
    assert _norm(extracted_observables=[_obs("ip_address", ["10.0.0.0/8", "192.168.0.0/16"], "network")]).rule_modality == "rule"
    # A real list of dotted quads / hashes still does.
    assert _norm(extracted_observables=[_obs("ip_address", ["10.0.0.1", "192.0.2.10"], "network")]).rule_modality == "indicator_match"
    assert _norm(extracted_observables=[_obs("file_hash", ["a" * 32, "b" * 40])]).rule_modality == "indicator_match"


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
