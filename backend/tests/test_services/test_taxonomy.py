"""Tests for the canonical taxonomy resolver.

We test the resolver dispatcher + a handful of representative cases per
vendor. The point is to catch regressions when mappings are edited and
to verify the contract that the resolver always returns three lists,
each non-empty (with at least `["unknown"]`).
"""

import pytest

from app.parsers.base import ParsedRule
from app.services.taxonomy import (
    DATA_SOURCES,
    EVENT_TYPES,
    PLATFORMS,
    UNKNOWN,
    resolve_for_repo,
)


def _make_parsed(source: str, **overrides) -> ParsedRule:
    """Build a minimal ParsedRule with the fields the resolvers actually read."""
    defaults = dict(
        source=source,
        file_path="rules/test.yml",
        raw_content="",
        title="Test rule",
        description="Test",
        author=None,
        status="stable",
        severity="medium",
        log_source={},
        tags=[],
        mitre_attack={"tactics": [], "techniques": []},
        detection_logic_raw={},
        false_positives=[],
        extra={},
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


# ── Resolver dispatcher contract ────────────────────────────────────────


def test_resolve_unknown_repo_raises():
    parsed = _make_parsed(source="not_a_real_repo")
    with pytest.raises(ValueError, match="No taxonomy resolver"):
        resolve_for_repo("not_a_real_repo", parsed)


def test_resolver_always_returns_three_lists():
    """Every resolver must return platforms, data_sources, event_types — all
    non-empty (at minimum [UNKNOWN])."""
    for repo in ["sigma", "elastic", "splunk", "sublime",
                 "elastic_protections", "lolrmm", "elastic_hunting", "sentinel"]:
        # Empty parsed rule — should still produce the contract shape
        parsed = _make_parsed(source=repo)
        result = resolve_for_repo(repo, parsed)
        assert "platforms" in result
        assert "data_sources" in result
        assert "event_types" in result
        for key in ("platforms", "data_sources", "event_types"):
            assert isinstance(result[key], list)
            assert len(result[key]) >= 1, f"{repo}.{key} was empty"


def test_resolver_returns_only_canonical_values():
    """Every value in every output list must be in the canonical vocabulary."""
    parsed = _make_parsed(source="sigma", log_source={"product": "windows", "category": "process_creation"})
    result = resolve_for_repo("sigma", parsed)
    for v in result["platforms"]:
        assert v in PLATFORMS, f"{v!r} not in canonical PLATFORMS"
    for v in result["data_sources"]:
        assert v in DATA_SOURCES, f"{v!r} not in canonical DATA_SOURCES"
    for v in result["event_types"]:
        assert v in EVENT_TYPES, f"{v!r} not in canonical EVENT_TYPES"


# ── Sigma vendor ────────────────────────────────────────────────────────


def test_sigma_windows_process_creation():
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "windows", "category": "process_creation"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["windows"]
    assert "sysmon" in result["data_sources"]
    assert "windows_security_event_log" in result["data_sources"]
    assert result["event_types"] == ["process_creation"]


def test_sigma_aws_cloudtrail():
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "aws", "service": "cloudtrail"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["aws"]
    assert result["data_sources"] == ["aws_cloudtrail"]
    assert result["event_types"] == ["api_call"]


def test_sigma_unknown_product_returns_unknown():
    parsed = _make_parsed(source="sigma", log_source={"product": "fictional_xyz"})
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == [UNKNOWN]
    assert result["data_sources"] == [UNKNOWN]
    assert result["event_types"] == [UNKNOWN]


# ── Elastic vendor ──────────────────────────────────────────────────────


def test_elastic_aws_cloudtrail_index():
    parsed = _make_parsed(
        source="elastic",
        extra={"index": ["logs-aws.cloudtrail-default-2024.01"]},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "aws" in result["platforms"]
    assert "aws_cloudtrail" in result["data_sources"]
    assert "api_call" in result["event_types"]


def test_elastic_multi_source_rule():
    """A rule that lists multiple indices unions all their canonical values."""
    parsed = _make_parsed(
        source="elastic",
        extra={
            "index": [
                "logs-endpoint.events.process-default",
                "logs-crowdstrike.fdr-default",
                "logs-windows.sysmon_operational-default",
            ]
        },
    )
    result = resolve_for_repo("elastic", parsed)
    # Should have all three platforms (endpoint indexes are cross-platform)
    assert "windows" in result["platforms"]
    # Should have multiple data sources
    assert "elastic_defend" in result["data_sources"]
    assert "crowdstrike_fdr" in result["data_sources"]
    assert "sysmon" in result["data_sources"]


def test_elastic_falls_back_to_integration():
    """If no index pattern matches, fall back to integration plugin name."""
    parsed = _make_parsed(
        source="elastic",
        extra={"index": ["nonexistent-pattern-*"], "integration": ["okta"]},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "okta" in result["platforms"]
    assert "okta_system_log" in result["data_sources"]


# ── Splunk vendor ───────────────────────────────────────────────────────


def test_splunk_sysmon_label():
    parsed = _make_parsed(
        source="splunk",
        extra={"data_source": ["Sysmon EventID 10"]},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "windows" in result["platforms"]
    assert "sysmon" in result["data_sources"]
    assert "process_creation" in result["event_types"]


def test_splunk_aws_security_lake_label():
    parsed = _make_parsed(
        source="splunk",
        extra={"data_source": ["ASL AWS CloudTrail"]},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "aws" in result["platforms"]
    assert "aws_security_lake" in result["data_sources"]


# ── Sublime vendor (always email) ───────────────────────────────────────


def test_sublime_always_email():
    """Sublime rules always resolve to email, regardless of input."""
    parsed = _make_parsed(source="sublime")
    result = resolve_for_repo("sublime", parsed)
    assert result["platforms"] == ["email"]
    assert result["data_sources"] == ["email_message_metadata"]
    assert result["event_types"] == ["email_message"]


# ── Sentinel vendor ─────────────────────────────────────────────────────


def test_sentinel_aws_security_hub_connector():
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [
                {"connectorId": "AWSSecurityHub", "dataTypes": ["AWSSecurityHubFindings"]}
            ]
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    assert "aws" in result["platforms"]
    assert "aws_security_hub" in result["data_sources"]


def test_sentinel_security_alert_data_type():
    """SecurityAlert dataType always contributes the siem_alert data source."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [
                {
                    "connectorId": "MicrosoftThreatProtection",
                    "dataTypes": ["SecurityAlert"],
                }
            ]
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    assert "siem_alert" in result["data_sources"]
    assert "defender_endpoint" in result["data_sources"]


# ── Elastic Protections vendor ──────────────────────────────────────────


def test_elastic_protections_always_elastic_defend():
    parsed = _make_parsed(
        source="elastic_protections",
        extra={"os_list": ["windows", "linux"]},
        detection_logic_raw="process where event.action == 'start'",
    )
    result = resolve_for_repo("elastic_protections", parsed)
    assert "elastic_defend" in result["data_sources"]
    assert "windows" in result["platforms"]
    assert "linux" in result["platforms"]
    assert "process_creation" in result["event_types"]


def test_elastic_protections_eql_query_head_parsing():
    """The EQL query head determines the event type."""
    cases = [
        ("process where ...", "process_creation"),
        ("file where ...", "file_event"),
        ("network where ...", "network_connection"),
        ("registry where ...", "registry_event"),
    ]
    for query, expected_event_type in cases:
        parsed = _make_parsed(
            source="elastic_protections",
            extra={"os_list": ["windows"]},
            detection_logic_raw=query,
        )
        result = resolve_for_repo("elastic_protections", parsed)
        assert expected_event_type in result["event_types"], f"Failed for query {query!r}"


# ── LOLRMM vendor ───────────────────────────────────────────────────────


def test_lolrmm_windows_process_creation():
    parsed = _make_parsed(
        source="lolrmm",
        log_source={"product": "windows", "category": "process_creation"},
    )
    result = resolve_for_repo("lolrmm", parsed)
    assert result["platforms"] == ["windows"]
    assert "sysmon" in result["data_sources"]
    assert "process_creation" in result["event_types"]


# ── Elastic Hunting vendor ──────────────────────────────────────────────


def test_elastic_hunting_always_includes_hunting_query():
    """Every hunting query gets the hunting_query event type."""
    parsed = _make_parsed(
        source="elastic_hunting",
        extra={"integration": ["aws.cloudtrail"]},
        detection_logic_raw="from logs-aws.cloudtrail* | where ...",
    )
    result = resolve_for_repo("elastic_hunting", parsed)
    assert "hunting_query" in result["event_types"]
    assert "aws" in result["platforms"]
    assert "aws_cloudtrail" in result["data_sources"]


def test_elastic_hunting_extracts_index_from_query():
    """The resolver parses `FROM logs-foo*` patterns out of ES|QL queries."""
    parsed = _make_parsed(
        source="elastic_hunting",
        detection_logic_raw="FROM logs-azure.signinlogs-default | where ...",
    )
    result = resolve_for_repo("elastic_hunting", parsed)
    assert "azure_ad" in result["platforms"]
    assert "entra_id_signin" in result["data_sources"]
