"""Tests for Sentinel/KQL field extraction."""

import re

import pytest
from app.services.field_extractor import extract_sentinel_fields


class TestSentinelTableExtraction:
    """Test KQL table reference extraction."""

    def test_extract_simple_table(self):
        """Extract table from simple KQL query."""
        query = 'SecurityEvent | where EventID == 4688'
        result = extract_sentinel_fields(query)

        assert "SecurityEvent" in result.source_tables
        assert "4688" in result.event_ids

    def test_extract_device_process_events(self):
        """Extract MDE table."""
        query = 'DeviceProcessEvents | where FileName =~ "powershell.exe"'
        result = extract_sentinel_fields(query)

        assert "DeviceProcessEvents" in result.source_tables
        assert "FileName" in result.fields_used
        assert "powershell.exe" in result.process_names

    def test_extract_union_tables(self):
        """Extract tables from union operator."""
        query = 'union SecurityEvent, SigninLogs | where EventID == 4625'
        result = extract_sentinel_fields(query)

        assert "SecurityEvent" in result.source_tables
        assert "SigninLogs" in result.source_tables

    def test_extract_join_table(self):
        """Extract tables from join operator."""
        query = '''SecurityEvent
| where EventID == 4624
| join kind=inner (
    SigninLogs
    | where ResultType == 0
) on AccountName'''
        result = extract_sentinel_fields(query)

        assert "SecurityEvent" in result.source_tables
        assert "SigninLogs" in result.source_tables
        assert result.query_complexity == "complex"


class TestSentinelFieldExtraction:
    """Test field extraction from where clauses."""

    def test_extract_equality(self):
        """Extract fields from == comparison."""
        query = 'SecurityEvent | where EventID == 4688 | where Process == "cmd.exe"'
        result = extract_sentinel_fields(query)

        assert "EventID" in result.fields_used
        assert "4688" in result.event_ids

    def test_extract_case_insensitive(self):
        """Extract from =~ comparison."""
        query = 'DeviceProcessEvents | where FileName =~ "powershell.exe"'
        result = extract_sentinel_fields(query)

        assert "FileName" in result.fields_used
        assert "powershell.exe" in result.process_names

    def test_extract_not_equals(self):
        """Extract negated fields from != operator."""
        query = 'SigninLogs | where ResultType != 0'
        result = extract_sentinel_fields(query)

        assert "ResultType" in result.fields_used
        negated = [o for o in result.observables if o.negated]
        assert len(negated) == 1

    def test_extract_contains_operator(self):
        """Extract from contains operator."""
        query = 'DeviceProcessEvents | where ProcessCommandLine contains "-enc"'
        result = extract_sentinel_fields(query)

        assert "ProcessCommandLine" in result.fields_used
        obs = [o for o in result.observables if o.field == "ProcessCommandLine"]
        assert len(obs) > 0
        assert obs[0].type == "process"
        assert obs[0].subtype == "command_line_pattern"

    def test_extract_has_operator(self):
        """Extract from has operator."""
        query = 'DeviceProcessEvents | where ProcessCommandLine has "certutil"'
        result = extract_sentinel_fields(query)

        assert "ProcessCommandLine" in result.fields_used

    def test_extract_in_operator(self):
        """Extract from in operator with list."""
        query = 'DeviceProcessEvents | where FileName in ("cmd.exe", "powershell.exe", "wscript.exe")'
        result = extract_sentinel_fields(query)

        assert "FileName" in result.fields_used
        assert "cmd.exe" in result.process_names
        assert "powershell.exe" in result.process_names
        assert "wscript.exe" in result.process_names

    def test_extract_in_numeric(self):
        """Extract numeric values from in operator."""
        query = 'SecurityEvent | where EventID in (4624, 4625, 4634)'
        result = extract_sentinel_fields(query)

        assert "EventID" in result.fields_used
        assert "4624" in result.event_ids
        assert "4625" in result.event_ids
        assert "4634" in result.event_ids


class TestSentinelProjectExtend:
    """Test project and extend field extraction."""

    def test_extract_project_fields(self):
        """Extract fields from project operator."""
        query = 'SecurityEvent | where EventID == 4688 | project TimeGenerated, Account, Computer, EventID'
        result = extract_sentinel_fields(query)

        assert "TimeGenerated" in result.fields_used
        assert "Account" in result.fields_used
        assert "Computer" in result.fields_used

    def test_extend_source_fields_yes_targets_no(self):
        """extend targets are DERIVED columns (issue #6 rebuild) — the
        telemetry field is the one on the right-hand side."""
        query = 'SecurityEvent | extend AccountDomain = split(Account, "\\\\")[0]'
        result = extract_sentinel_fields(query)

        assert "Account" in result.fields_used
        assert "AccountDomain" not in result.fields_used


class TestSentinelLetStatements:
    """Test handling of let statements."""

    def test_let_variable_handling(self):
        """Let statements should not break table extraction."""
        query = 'let timeframe = 1d; SecurityEvent | where TimeGenerated > ago(timeframe) | where EventID == 4688'
        result = extract_sentinel_fields(query)

        assert "SecurityEvent" in result.source_tables
        assert "4688" in result.event_ids
        assert result.query_complexity == "moderate"  # let makes it moderate


class TestSentinelNetworkFields:
    """Test network field extraction."""

    def test_extract_remote_port(self):
        """Extract network port from MDE table."""
        query = 'DeviceNetworkEvents | where RemotePort == 443'
        result = extract_sentinel_fields(query)

        assert "DeviceNetworkEvents" in result.source_tables
        assert "RemotePort" in result.fields_used
        assert "443" in result.network_indicators

    def test_extract_remote_ip(self):
        """Extract IP address."""
        query = 'DeviceNetworkEvents | where RemoteIP == "10.0.0.1"'
        result = extract_sentinel_fields(query)

        assert "RemoteIP" in result.fields_used
        assert "10.0.0.1" in result.network_indicators


class TestSentinelComplexity:
    """Test query complexity assessment."""

    def test_simple_query(self):
        query = 'SecurityEvent | where EventID == 4688'
        result = extract_sentinel_fields(query)
        assert result.query_complexity == "simple"

    def test_moderate_let(self):
        query = 'let x = 1; SecurityEvent | where EventID == 4688'
        result = extract_sentinel_fields(query)
        assert result.query_complexity == "moderate"

    def test_complex_join(self):
        query = 'SecurityEvent | join kind=inner (SigninLogs) on Account'
        result = extract_sentinel_fields(query)
        assert result.query_complexity == "complex"

    def test_complex_union(self):
        query = 'union SecurityEvent, SigninLogs | where EventID == 4688'
        result = extract_sentinel_fields(query)
        assert result.query_complexity == "complex"


class TestSentinelSigninLogs:
    """Test authentication field extraction."""

    def test_extract_signin_fields(self):
        """Extract authentication fields from SigninLogs."""
        query = 'SigninLogs | where ResultType != 0'
        result = extract_sentinel_fields(query)

        assert "SigninLogs" in result.source_tables
        assert "ResultType" in result.fields_used


class TestKqlRebuildFixture:
    """Issue #6 rebuild fixture — the KQL junk classes the 2026-08-26
    baseline measured (1,675 junk fields_used entries, KQL fragments in
    source_tables)."""

    def test_sort_by_desc_is_not_a_field_name(self):
        query = (
            "SecurityEvent | summarize count() by Account "
            "| sort by RiskScore desc, EventTime desc"
        )
        r = extract_sentinel_fields(query)
        assert "RiskScore" in r.fields_used
        assert "EventTime" in r.fields_used
        assert not any(" " in f for f in r.fields_used)

    def test_bin_in_by_clause_yields_the_field(self):
        query = (
            "SecurityEvent | summarize count() by bin(TimeGenerated, 1d), Account"
        )
        r = extract_sentinel_fields(query)
        assert "TimeGenerated" in r.fields_used
        assert "Account" in r.fields_used
        assert "1d)" not in r.fields_used

    def test_multi_let_script_keeps_tables_clean(self):
        query = (
            'let watch = dynamic(["a.com", "b.com"]);\n'
            "let MDE_Results = DeviceProcessEvents | where FileName =~ \"rundll32.exe\";\n"
            "let CredentialActivity = SecurityEvent | where EventID == 4624;\n"
            "union MDE_Results, CredentialActivity | sort by TimeGenerated desc"
        )
        r = extract_sentinel_fields(query)
        assert "DeviceProcessEvents" in r.source_tables
        assert "SecurityEvent" in r.source_tables
        # let-bound names are NOT tables; no fragment ever is.
        assert "MDE_Results" not in r.source_tables
        assert "CredentialActivity" not in r.source_tables
        assert not any(re.search(r"\s", t) for t in r.source_tables)

    def test_externaldata_let_does_not_leak_fragments(self):
        query = (
            "let feed = externaldata(Activity:string)[\"https://x/y.csv\"] "
            "with (format=\"csv\");\n"
            "CommonSecurityLog | where DeviceAction == \"deny\""
        )
        r = extract_sentinel_fields(query)
        assert "CommonSecurityLog" in r.source_tables
        assert all("string" not in t for t in r.source_tables)

    def test_summarize_agg_args_yes_aliases_no(self):
        query = (
            "SecurityEvent | summarize Total = count(), Distinct = dcount(Account), "
            "FirstSeen = min(TimeGenerated) by Computer"
        )
        r = extract_sentinel_fields(query)
        assert "Account" in r.fields_used
        assert "TimeGenerated" in r.fields_used
        assert "Computer" in r.fields_used
        assert "Total" not in r.fields_used
        assert "FirstSeen" not in r.fields_used

    def test_scalar_wrappers_unwrap_to_the_column(self):
        query = 'DeviceProcessEvents | where tolower(FileName) == "mimikatz.exe"'
        r = extract_sentinel_fields(query)
        assert "FileName" in r.fields_used
        assert "mimikatz.exe" in r.process_names

    def test_join_subpipeline_and_keys(self):
        query = (
            "SecurityEvent | where EventID == 4624 "
            "| join kind=inner (SigninLogs | where ResultType == 0) on AccountName"
        )
        r = extract_sentinel_fields(query)
        assert "SigninLogs" in r.source_tables
        assert "AccountName" in r.fields_used

    def test_has_any_list(self):
        query = (
            'DeviceProcessEvents | where ProcessCommandLine has_any '
            '("-enc", "-encodedcommand")'
        )
        r = extract_sentinel_fields(query)
        obs = [o for o in r.observables if o.field == "ProcessCommandLine"]
        assert obs and set(obs[0].values) == {"-enc", "-encodedcommand"}

    def test_parse_captures_are_derived(self):
        query = (
            'Syslog | parse SyslogMessage with * "user=" TargetUser " " * '
            "| where TargetUser != \"root\""
        )
        r = extract_sentinel_fields(query)
        assert "SyslogMessage" in r.fields_used
        assert "TargetUser" not in r.fields_used


class TestSentinelEdgeCases:
    """Test edge cases."""

    def test_empty_query(self):
        result = extract_sentinel_fields("")
        assert result.fields_used == []

    def test_none_query(self):
        result = extract_sentinel_fields(None)
        assert result.fields_used == []

    def test_multiline_query(self):
        """Handle multi-line KQL queries."""
        query = """SecurityEvent
| where EventID == 4688
| where Process != "svchost.exe"
| project TimeGenerated, Account, Process
"""
        result = extract_sentinel_fields(query)

        assert "SecurityEvent" in result.source_tables
        assert "4688" in result.event_ids
        assert "TimeGenerated" in result.fields_used

    def test_summarize_by_fields(self):
        """Extract fields from summarize by clause."""
        query = 'SecurityEvent | where EventID == 4688 | summarize count() by Account, Computer'
        result = extract_sentinel_fields(query)

        assert "Account" in result.fields_used
        assert "Computer" in result.fields_used
