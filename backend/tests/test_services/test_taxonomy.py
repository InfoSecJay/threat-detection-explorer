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
        assert "matched" in result
        assert "fingerprint" in result
        for key in ("platforms", "data_sources", "event_types"):
            assert isinstance(result[key], list)
            assert len(result[key]) >= 1, f"{repo}.{key} was empty"


def test_resolver_matched_false_for_empty_input():
    """An empty rule for a vendor without defaults should produce matched=False.

    Vendors with `always_includes` in their mapping (elastic_protections,
    elastic_hunting, lolrmm, sentinel, sublime) inject signal into every
    rule by design and are excluded here — they can never produce an
    "unmapped" rule, which is architecturally correct for closed sets
    like agent-resident behavior rules.
    """
    for repo in ["sigma", "elastic", "splunk"]:
        parsed = _make_parsed(source=repo)
        result = resolve_for_repo(repo, parsed)
        assert result["matched"] is False, f"{repo} should report matched=False on empty input"


def test_resolver_matched_true_for_mapped_input():
    """A rule whose logsource hits the mapping should report matched=True."""
    parsed = _make_parsed(
        source="sigma",
        log_source={"product": "windows", "category": "process_creation"},
    )
    result = resolve_for_repo("sigma", parsed)
    assert result["matched"] is True


def test_resolver_fingerprint_is_stable_across_calls():
    """Identical inputs produce identical fingerprints."""
    ls = {"product": "linux", "service": "auditd"}
    a = resolve_for_repo("sigma", _make_parsed(source="sigma", log_source=ls))
    b = resolve_for_repo("sigma", _make_parsed(source="sigma", log_source=ls))
    assert a["fingerprint"] == b["fingerprint"]
    assert a["fingerprint"].startswith("sigma:")


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
    assert "azure" in result["platforms"]
    assert "entra_id_signin" in result["data_sources"]


# ── Elastic tag walking + rule_type fallback ─────────────────────────────


def test_elastic_tags_resolve_to_os_and_data_source():
    """Tags like `Data Source: Elastic Defend` feed into the resolver."""
    parsed = _make_parsed(
        source="elastic",
        tags=["Domain: Endpoint", "OS: Windows", "Data Source: Elastic Defend"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert "windows" in result["platforms"]
    assert "elastic_defend" in result["data_sources"]
    assert result["matched"] is True


def test_elastic_ml_rule_gets_ml_detection_event_type():
    """type=machine_learning rules fall back to ml_detection event_type."""
    parsed = _make_parsed(
        source="elastic",
        extra={"type": "machine_learning", "integration": ["endpoint"]},
        tags=["OS: Linux", "Rule Type: ML"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert "ml_detection" in result["event_types"]
    assert "elastic_ml" in result["data_sources"]
    # Integration `endpoint` still contributes the platform list.
    assert "linux" in result["platforms"]


def test_elastic_higher_order_alerts_correlation():
    """`.alerts-security-*` indices mark higher-order / alert-on-alert rules."""
    parsed = _make_parsed(
        source="elastic",
        extra={"index": [".alerts-security.alerts-default"]},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "alert_correlation" in result["event_types"]
    assert "elastic_siem_alerts" in result["data_sources"]


def test_elastic_filebeat_no_longer_bleeds_into_aws():
    """Network rules with filebeat-* must not pick up aws_cloudtrail anymore."""
    parsed = _make_parsed(
        source="elastic",
        extra={
            "index": ["packetbeat-*", "filebeat-*", "logs-network_traffic.*"],
            "integration": ["network_traffic"],
        },
        tags=["Domain: Network"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert "aws" not in result["platforms"]
    assert "aws_cloudtrail" not in result["data_sources"]
    assert "network_appliance" in result["platforms"]
    assert "network_traffic_logs" in result["data_sources"]


def test_elastic_os_tag_overrides_integration_platform_list():
    """`OS: Windows` tag narrows platforms to [windows] even when the
    integration (`endpoint` / `system`) supports more OSes. Tag declares
    authorial intent; integration declares capability."""
    parsed = _make_parsed(
        source="elastic",
        extra={
            "integration": ["endpoint", "system"],
            "index": ["logs-endpoint.events.process-*", "winlogbeat-*"],
        },
        tags=["Domain: Endpoint", "OS: Windows"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert result["platforms"] == ["windows"]
    # Data sources + event types still union across the signals.
    assert "elastic_defend" in result["data_sources"]
    assert "windows_security_event_log" in result["data_sources"]


def test_elastic_multi_os_tags_narrow_to_exact_set():
    """`OS: Windows` + `OS: Linux` → [windows, linux]. macOS excluded
    even though endpoint integration supports it."""
    parsed = _make_parsed(
        source="elastic",
        extra={"integration": ["endpoint"]},
        tags=["OS: Windows", "OS: Linux"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert set(result["platforms"]) == {"windows", "linux"}


def test_elastic_no_os_tag_keeps_integration_platform_union():
    """Without any OS tag, fall back to the integration's capability set."""
    parsed = _make_parsed(
        source="elastic",
        extra={"integration": ["endpoint"]},
        tags=["Domain: Endpoint"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert set(result["platforms"]) == {"windows", "linux", "macos"}


def test_elastic_eql_head_extracts_event_type():
    """EQL queries start with `<category> where ...` — that category
    maps directly to a canonical event_type."""
    parsed = _make_parsed(
        source="elastic",
        extra={
            "type": "eql",
            "language": "eql",
            "integration": ["endpoint"],
        },
        tags=["OS: Linux"],
        detection_logic_raw={"type": "eql", "query": 'process where process.name == "bash"'},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "process_creation" in result["event_types"]


def test_elastic_eql_file_and_network_categories():
    """EQL `file where ...` → file_event, `network where ...` → network_connection."""
    for eql_cat, expected in [
        ("file", "file_event"),
        ("network", "network_connection"),
        ("registry", "registry_event"),
        ("dns", "dns_query"),
    ]:
        parsed = _make_parsed(
            source="elastic",
            extra={"type": "eql", "language": "eql", "integration": ["endpoint"]},
            tags=["OS: Windows"],
            detection_logic_raw={"type": "eql", "query": f'{eql_cat} where true'},
        )
        result = resolve_for_repo("elastic", parsed)
        assert expected in result["event_types"], f"{eql_cat} did not produce {expected}"


def test_elastic_promotion_rule_gets_platform_alert_event_type():
    """`metadata.promotion = true` means the rule wraps an external
    detection (Endgame / QRadar / CrowdStrike / another SIEM) into an
    Elastic alert. It should emit `platform_alert` event_type, distinct
    from `alert_correlation` (which is reserved for the SIEM consuming
    its own alert stream)."""
    parsed = _make_parsed(
        source="elastic",
        extra={
            "type": "query",
            "language": "kuery",
            "index": ["endgame-*"],
            "promotion": True,
        },
    )
    result = resolve_for_repo("elastic", parsed)
    assert "platform_alert" in result["event_types"]
    assert "elastic_endgame" in result["data_sources"]
    # platform_alert (external alert ingested) is not the same as
    # alert_correlation (SIEM alert-on-alert).
    assert "alert_correlation" not in result["event_types"]


def test_elastic_os_tag_also_narrows_data_sources():
    """When OS tag narrows platforms, data_sources that can't produce
    telemetry on those platforms are pruned. Elastic's `system`
    integration supports both linux_syslog AND windows_security_event_log;
    a Windows-tagged rule should drop linux_syslog."""
    parsed = _make_parsed(
        source="elastic",
        extra={"integration": ["system", "endpoint"]},
        tags=["OS: Windows"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert result["platforms"] == ["windows"]
    # linux_syslog can't produce Windows telemetry — must be dropped.
    assert "linux_syslog" not in result["data_sources"]
    # Cross-platform endpoint agents still apply on Windows — kept.
    assert "elastic_defend" in result["data_sources"]
    # Windows-specific source stays.
    assert "windows_security_event_log" in result["data_sources"]


def test_data_source_narrowing_preserves_cross_platform_sources():
    """Cross-OS sources (osquery, elastic_defend) apply on any of
    their supported platforms. A Linux rule using elastic_defend
    should keep it, not drop it."""
    parsed = _make_parsed(
        source="elastic",
        extra={"integration": ["endpoint"]},
        tags=["OS: Linux"],
    )
    result = resolve_for_repo("elastic", parsed)
    assert result["platforms"] == ["linux"]
    assert "elastic_defend" in result["data_sources"]


def test_data_source_narrowing_is_noop_when_no_os_constraint():
    """Without an OS tag, platforms come from the full integration
    capability list. Data sources all intersect with at least one of
    those platforms, so none should be pruned."""
    parsed = _make_parsed(
        source="elastic",
        extra={"integration": ["system"]},
    )
    result = resolve_for_repo("elastic", parsed)
    # system → platforms [windows, linux], data_sources [linux_syslog,
    # windows_security_event_log]. Both still apply (linux_syslog on
    # linux, windows_security_event_log on windows).
    assert "linux_syslog" in result["data_sources"]
    assert "windows_security_event_log" in result["data_sources"]


def test_splunk_datamodel_is_authoritative_over_data_source_labels():
    """`tstats ... datamodel=Endpoint.Processes` should produce
    event_types=[process_creation] ONLY — not the 4-way union
    (authentication + audit_event + network_connection + process_creation)
    we were seeing before the tiered resolver. The datamodel overrides
    capability signals from coarse feed labels."""
    parsed = _make_parsed(
        source="splunk",
        extra={
            "data_source": ["Sysmon EventID 1", "Windows Event Log Security", "CrowdStrike"],
        },
        detection_logic_raw={
            "search": "| tstats count FROM datamodel=Endpoint.Processes WHERE Processes.process_name = 'cipher.exe'",
        },
    )
    result = resolve_for_repo("splunk", parsed)
    # event_type narrowed to what the datamodel says — no authentication
    # / audit_event / network_connection leaking in.
    assert "process_creation" in result["event_types"]
    assert "authentication" not in result["event_types"]
    assert "audit_event" not in result["event_types"]
    assert "network_connection" not in result["event_types"]


def test_splunk_macro_okta_authoritative():
    """`okta` macro always means authentication — authoritative event_type."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={
            "search": "`okta` eventType = security.threat.detected | stats count",
        },
    )
    result = resolve_for_repo("splunk", parsed)
    assert "okta" in result["platforms"]
    assert "okta_system_log" in result["data_sources"]
    assert result["event_types"] == ["authentication"]


def test_splunk_macro_mcp_server_maps_to_llm():
    """MCP server macro maps to llm platform + llm_service_logs."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={"search": "`mcp_server` direction=inbound | stats count"},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "llm" in result["platforms"]
    assert "llm_service_logs" in result["data_sources"]
    assert "api_call" in result["event_types"]


def test_splunk_kubernetes_macro_maps_correctly():
    """`kubernetes_container_controller` macro should NOT be unknown
    anymore — previously showed [unknown]/[unknown]/[unknown]."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={"search": "`kubernetes_container_controller` | stats count"},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "kubernetes" in result["platforms"]
    assert "kubernetes_audit" in result["data_sources"]
    assert "audit_event" in result["event_types"]


def test_splunk_zscaler_proxy_macro_maps_correctly():
    """`zscaler_proxy` macro previously unmapped."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={"search": "`zscaler_proxy` action=blocked | stats count"},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "network_appliance" in result["platforms"]
    assert "proxy_logs" in result["data_sources"]
    assert result["event_types"] == ["http_request"]


def test_splunk_from_datamodel_no_equals_syntax():
    """`| from datamodel Web.Web` (no `=`) should still trigger the
    Web datamodel mapping. Used by Log4Shell rules."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={
            "search": "| from datamodel Web.Web | regex _raw=\"jndi\" | stats count",
        },
    )
    result = resolve_for_repo("splunk", parsed)
    assert "network_appliance" in result["platforms"]
    assert "http_request" in result["event_types"]


def test_splunk_sysmon_macro_alone_does_not_force_event_type():
    """Bare `sysmon` macro should contribute platforms + data_sources
    but NOT force a single event_type (sysmon has 27 event codes)."""
    # Use a search with no other signal except the macro.
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={"search": "`sysmon` TargetImage=lsass.exe | stats count"},
    )
    result = resolve_for_repo("splunk", parsed)
    assert "windows" in result["platforms"]
    assert "sysmon" in result["data_sources"]
    # No authoritative event_type came from the bare macro — should fall
    # through to UNKNOWN (no capability signals set anything).
    assert result["event_types"] == ["unknown"]


def test_elastic_eql_sequence_extracts_event_types_from_brackets():
    """EQL `sequence ... [<cat> where ...]` blocks should contribute
    event_types. Elastic Defend rules use this heavily; the previous
    regex only matched the query head and missed all sequence rules."""
    query = (
        'sequence by host.id with maxspan=5m '
        '[process where event.action == "start"] '
        '[network where event.type == "connection_attempt"]'
    )
    parsed = _make_parsed(
        source="elastic",
        extra={"type": "eql", "language": "eql", "integration": ["endpoint"]},
        tags=["OS: Windows"],
        detection_logic_raw={"type": "eql", "query": query},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "process_creation" in result["event_types"]
    assert "network_connection" in result["event_types"]


def test_elastic_protections_sequence_extracts_event_types():
    """Elastic Protections (agent rules) use EQL sequence heavily.
    Previously ~451 rules had event_types=[unknown] because the
    extractor only matched `<cat> where` at the query head."""
    query = (
        'sequence with maxspan=1m '
        '[process where event.action == "start"] '
        '[file where event.action == "modification"]'
    )
    parsed = _make_parsed(
        source="elastic_protections",
        detection_logic_raw=query,
    )
    result = resolve_for_repo("elastic_protections", parsed)
    assert "process_creation" in result["event_types"]
    assert "file_event" in result["event_types"]


def test_elastic_kql_event_category_extraction():
    """KQL rules use `event.category:process` instead of EQL's
    `process where`. Our KQL extractor should pull the category."""
    parsed = _make_parsed(
        source="elastic",
        extra={"type": "query", "language": "kuery"},
        tags=["OS: Linux"],
        detection_logic_raw={
            "type": "query",
            "query": 'host.os.type:linux and event.category:process and event.action:exec',
        },
    )
    result = resolve_for_repo("elastic", parsed)
    assert "process_creation" in result["event_types"]


def test_elastic_alerts_security_has_cross_platform_now():
    """Higher-order rules querying `.alerts-security-*` used to show
    platforms=[unknown] because no signal set a platform. The index
    pattern now provides cross_platform explicitly."""
    parsed = _make_parsed(
        source="elastic",
        extra={"index": [".alerts-security.alerts-default"]},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "cross_platform" in result["platforms"]
    assert "alert_correlation" in result["event_types"]


def test_splunk_aws_cloudwatchlogs_eks_macro():
    """`aws_cloudwatchlogs_eks` macro (EKS audit logs) previously
    unmapped — was the rule the user reported as broken."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={
            "search": '`aws_cloudwatchlogs_eks` "user.username"="system:anonymous" | stats count',
        },
    )
    result = resolve_for_repo("splunk", parsed)
    assert "kubernetes" in result["platforms"]
    assert "kubernetes_audit" in result["data_sources"]
    assert "audit_event" in result["event_types"]


def test_splunk_cisco_isovalent_process_exec_macro():
    """Cisco Isovalent (Cilium Tetragon) eBPF process-exec feed."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={
            "search": '`cisco_isovalent_process_exec` process_name="curl" | stats count',
        },
    )
    result = resolve_for_repo("splunk", parsed)
    assert "kubernetes" in result["platforms"]
    assert result["event_types"] == ["process_creation"]


def test_splunk_risk_datamodel_is_alert_correlation():
    """`tstats ... datamodel=Risk` aggregates risk scores across other
    rules — that's alert-on-alert correlation, not raw telemetry."""
    parsed = _make_parsed(
        source="splunk",
        detection_logic_raw={
            "search": '| tstats sum(All_Risk.calculated_risk_score) FROM datamodel=Risk',
        },
    )
    result = resolve_for_repo("splunk", parsed)
    assert "cross_platform" in result["platforms"]
    assert "siem_alert" in result["data_sources"]
    assert "alert_correlation" in result["event_types"]


def test_sentinel_kql_table_name_is_authoritative():
    """Sentinel resolver's Tier 1 — the query's first table name IS
    the data source. `AWSCloudTrail | where ...` → aws + aws_cloudtrail
    + api_call even without requiredDataConnectors declared."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [],
            "kql_tables": ["AWSCloudTrail"],
            "solution_folder": "Amazon Web Services",
            "entity_types": [],
        },
        detection_logic_raw='AWSCloudTrail | where EventName == "DeleteTrail"',
    )
    result = resolve_for_repo("sentinel", parsed)
    assert result["platforms"] == ["aws"]
    assert "aws_cloudtrail" in result["data_sources"]
    assert result["event_types"] == ["api_call"]


def test_sentinel_solution_folder_fallback_when_table_unmapped():
    """Tier 4 — when KQL table isn't in kql_tables and there's no
    connector, the `Solutions/<vendor>/` folder resolves."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [],
            "kql_tables": ["SomeNotMappedTable"],
            "solution_folder": "Acronis Cyber Protect Cloud",
            "entity_types": [],
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    assert "cross_platform" in result["platforms"]
    assert "antivirus_logs" in result["data_sources"]


def test_sentinel_veeam_is_cross_platform_not_linux():
    """Veeam Backup runs on Windows; only the syslog forwarder is
    Linux-format. Previously ALL 132 Veeam rules showed platforms=[linux]
    via the syslogama connector. Now the `Veeam_GetSecurityEvents` table
    mapping + solution folder fix the classification."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [{"connectorId": "syslogama", "dataTypes": ["Syslog"]}],
            "kql_tables": ["Veeam_GetSecurityEvents"],
            "solution_folder": "Veeam",
            "entity_types": [],
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    # Platform widened — now includes Windows (where Veeam runs).
    assert "windows" in result["platforms"] or "cross_platform" in result["platforms"]
    # Data source is application_logs (Veeam's own event stream), not
    # a generic linux_syslog misclassification.
    assert "application_logs" in result["data_sources"]


def test_sentinel_custom_log_cl_fallback():
    """`*_CL` custom-log tables (long tail of vendor marketplace
    connectors) get the `siem_alert` data_source but NOT a
    cross_platform platform tag -- the `*_cl` catch-all bucket used to
    poison platforms with `cross_platform`, which the Phase 2 audit
    flagged as a 50% mis-classification rate on Sentinel. When no tier
    resolves a platform, the result is `[unknown]` (more honest than
    silently `cross_platform`)."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [],
            "kql_tables": ["SomeExoticVendor_CL"],
            "solution_folder": "",
            "entity_types": [],
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    assert "cross_platform" not in result["platforms"]
    assert "siem_alert" in result["data_sources"]


def test_sentinel_entity_type_is_last_resort():
    """Entity types contribute event_type ONLY when no other tier fired.
    They never set platforms/data_sources."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            "requiredDataConnectors": [],
            "kql_tables": [],
            "solution_folder": "",
            "entity_types": ["MailMessage"],
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    # entity_type=MailMessage → email_message event_type, but platforms
    # and data_sources should still be unknown (entity doesn't describe
    # the telemetry source).
    assert "email_message" in result["event_types"]
    assert result["platforms"] == ["unknown"]
    assert result["data_sources"] == ["unknown"]


def test_sentinel_kql_table_beats_connector_when_both_present():
    """Tier 1 (table name) overrides Tier 2 (connector) for event_type
    when they disagree — the table is what the rule actually queries."""
    parsed = _make_parsed(
        source="sentinel",
        extra={
            # Connector says authentication, table says api_call
            "requiredDataConnectors": [{"connectorId": "azureactivedirectory", "dataTypes": []}],
            "kql_tables": ["AzureActivity"],
            "solution_folder": "",
            "entity_types": [],
        },
    )
    result = resolve_for_repo("sentinel", parsed)
    # Table AzureActivity → api_call (Tier 1 authoritative)
    assert "api_call" in result["event_types"]


def test_elastic_higher_order_rule_uses_alert_correlation_not_platform_alert():
    """`.alerts-security-*` rules are the SIEM's OWN alert stream —
    they should use alert_correlation, NOT platform_alert (which is
    reserved for external-product alerts being ingested)."""
    parsed = _make_parsed(
        source="elastic",
        extra={"index": [".alerts-security.alerts-default"]},
    )
    result = resolve_for_repo("elastic", parsed)
    assert "alert_correlation" in result["event_types"]
    assert "platform_alert" not in result["event_types"]
    assert "elastic_siem_alerts" in result["data_sources"]
