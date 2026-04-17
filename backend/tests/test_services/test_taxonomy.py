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


def test_sigma_resolver_first_match_wins_no_union():
    """Regression: the resolver used to union data_sources across all
    matching keys (most specific + all fallbacks), producing spurious
    multi-source results like [auditd, osquery, linux_syslog] when
    Sigma only said `product=linux, category=process_creation`.
    First-match-wins semantics mean the most specific entry's values
    are authoritative."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "linux", "category": "process_creation"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["linux"]
    assert result["event_types"] == ["process_creation"]
    # Since Sigma didn't say service, data_source should be [unknown],
    # NOT a speculative union of auditd+osquery+linux_syslog.
    assert result["data_sources"] == [UNKNOWN]


def test_sigma_linux_auditd_service_explicit():
    """Rules with `service: auditd` (no category) DO get a real data_source
    because the service is explicit in the rule."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "linux", "service": "auditd"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["linux"]
    assert result["data_sources"] == ["auditd"]
    assert result["event_types"] == ["audit_event"]


def test_sigma_linux_auditd_execve_compound():
    """Compound logsource (auditd service + execve category) matches
    the most-specific key and returns process_creation."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "linux", "service": "auditd", "category": "execve"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["linux"]
    assert result["data_sources"] == ["auditd"]
    assert result["event_types"] == ["process_creation"]


def test_sigma_linux_sshd_maps_to_syslog():
    """Explicit syslog-backed services (sshd, sudo, cron) map to
    linux_syslog — not guessed, they really do write to syslog/journald."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "linux", "service": "sshd"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["data_sources"] == ["linux_syslog"]
    assert result["event_types"] == ["audit_event"]


def test_sigma_macos_no_data_source_inference():
    """macOS rules don't have Sigma-level service info, so data_source
    is [unknown] — we don't infer osquery / Elastic Defend / etc."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "macos", "category": "process_creation"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["macos"]
    assert result["event_types"] == ["process_creation"]
    assert result["data_sources"] == [UNKNOWN]


def test_sigma_windows_process_creation_still_has_data_sources():
    """Windows mappings were deliberately left unchanged — the 'generic
    categories get both Sysmon and Windows Event Log' behavior is
    acknowledged as the intended Sigma compatibility semantic."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "windows", "category": "process_creation"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["windows"]
    assert "sysmon" in result["data_sources"]
    assert "windows_security_event_log" in result["data_sources"]
    assert result["event_types"] == ["process_creation"]


def test_sigma_unknown_product_returns_unknown():
    parsed = _make_parsed(source="sigma", log_source={"product": "fictional_xyz"})
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == [UNKNOWN]
    assert result["data_sources"] == [UNKNOWN]
    assert result["event_types"] == [UNKNOWN]


def test_sigma_granular_sysmon_categories_preserved():
    """Each Sigma Sysmon category maps to its own distinct event_type.

    Regression test for the design decision to NOT collapse related
    categories (file_delete, file_block_executable, etc.) into
    file_event. Each category is first-class so detection engineers
    can filter by the specific activity.
    """
    cases = [
        ("file_delete", "file_delete"),
        ("file_delete_detected", "file_delete_detected"),
        ("file_block_executable", "file_block_executable"),
        ("create_stream_hash", "create_stream_hash"),
        ("pipe_created", "pipe_created"),
        ("process_access", "process_access"),
        ("create_remote_thread", "create_remote_thread"),
        ("raw_access_thread", "raw_access_thread"),
        ("process_tampering", "process_tampering"),
        ("registry_add", "registry_add"),
        ("registry_set", "registry_set"),
        ("registry_rename", "registry_rename"),
        ("wmi_event", "wmi_event"),
        ("clipboard_capture", "clipboard_capture"),
        ("driver_load", "driver_load"),
    ]
    for sigma_category, expected_event_type in cases:
        parsed = _make_parsed(
            source="sigma",
            log_source={"product": "windows", "category": sigma_category},
        )
        result = resolve_for_repo("sigma", parsed)
        assert expected_event_type in result["event_types"], (
            f"Sigma category {sigma_category!r} should resolve to "
            f"event_type {expected_event_type!r}, got {result['event_types']}"
        )


def test_sigma_windows_security_channel_is_blanket_audit_event():
    """Windows Security/System/Application channels get blanket audit_event
    with NO inferred authentication tag. The design principle is no
    inference — per-EventID classification is future work."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "windows", "service": "security"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["event_types"] == ["audit_event"]
    # Must NOT contain authentication — that would be inference
    assert "authentication" not in result["event_types"]


def test_sigma_okta_is_api_call():
    """Okta System Log is API-driven per Okta's docs — not a mix of
    authentication + audit_event."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "okta", "service": "okta"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["event_types"] == ["api_call"]
    assert "authentication" not in result["event_types"]
    assert "audit_event" not in result["event_types"]


def test_sigma_m365_audit_vs_threat_management():
    """M365 has distinct services with different data_sources:
    - `threat_management` / `threat_detection` = Defender for O365 feed
    - `audit` = Unified Audit Log (REST API)
    - `exchange` = Exchange Online admin/mail flow
    """
    # threat_management -> Defender (not plain api_call)
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "m365", "service": "threat_management"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["data_sources"] == ["m365_defender"]
    assert result["event_types"] == ["audit_event"]

    # audit -> unified audit log, which IS REST API
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "m365", "service": "audit"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["data_sources"] == ["m365_audit"]
    assert result["event_types"] == ["api_call"]

    # exchange -> Exchange-specific feed
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "m365", "service": "exchange"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["data_sources"] == ["m365_exchange_audit"]


def test_sigma_azure_signin_is_authentication_not_api_call():
    """Azure sign-in logs ARE authentication events — not generic
    api_call — because the feed is exclusively sign-in activity.
    Platform is `azure` (we consolidated — dropped the separate
    azure_ad platform; data_source carries the Entra precision)."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "azure", "service": "signinlogs"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["azure"]
    assert result["data_sources"] == ["entra_id_signin"]
    assert result["event_types"] == ["authentication"]


def test_sigma_azure_consolidation():
    """All Azure services now resolve to platform=`azure` (no more
    separate azure_ad platform). Data source gives the precision."""
    cases = [
        ("activitylogs", "azure_activity", "api_call"),
        ("auditlogs", "entra_id_audit", "api_call"),
        ("riskdetection", "azure_risk_detection", "audit_event"),
        ("pim", "azure_pim", "audit_event"),
    ]
    for service, expected_ds, expected_et in cases:
        parsed = _make_parsed(
            source="sigma",
            log_source={"product": "azure", "service": service},
        )
        result = resolve_for_repo("sigma", parsed)
        assert result["platforms"] == ["azure"], f"service={service}"
        assert result["data_sources"] == [expected_ds], f"service={service}"
        assert result["event_types"] == [expected_et], f"service={service}"


def test_sigma_bare_category_rules():
    """Sigma has ~60 rules with no product that use format-agnostic
    categories (webserver, antivirus, database, proxy). The resolver
    must handle these via a bare category key lookup."""
    cases = [
        ("webserver", "network_appliance", "webserver_logs", "http_request"),
        ("antivirus", "cross_platform", "antivirus_logs", "audit_event"),
        ("database", "cross_platform", "database_logs", "audit_event"),
        ("proxy", "network_appliance", "proxy_logs", "http_request"),
        ("dns", "network_appliance", "dns_query_logs", "dns_query"),
    ]
    for category, expected_plat, expected_ds, expected_et in cases:
        parsed = _make_parsed(source="sigma", log_source={"category": category})
        result = resolve_for_repo("sigma", parsed)
        assert result["platforms"] == [expected_plat], f"category={category}"
        assert expected_ds in result["data_sources"], f"category={category}"
        assert expected_et in result["event_types"], f"category={category}"


def test_sigma_onelogin():
    """OneLogin uses `onelogin.events` as its service name (dot notation)."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "onelogin", "service": "onelogin.events"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["onelogin"]
    assert result["data_sources"] == ["onelogin_events"]
    assert result["event_types"] == ["api_call"]


def test_sigma_bitbucket():
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "bitbucket", "service": "audit"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["platforms"] == ["bitbucket"]
    assert result["data_sources"] == ["bitbucket_audit"]
    assert result["event_types"] == ["api_call"]


def test_sigma_application_frameworks():
    """Runtime framework rules (django, jvm, spring, etc.) are
    cross-platform with application_logs as the data_source."""
    for product in ["django", "jvm", "spring", "nodejs", "python", "opencanary"]:
        parsed = _make_parsed(
            source="sigma",
            log_source={"product": product, "category": "application"},
        )
        result = resolve_for_repo("sigma", parsed)
        assert result["platforms"] == ["cross_platform"], f"product={product}"
        assert result["data_sources"] == ["application_logs"], f"product={product}"


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
