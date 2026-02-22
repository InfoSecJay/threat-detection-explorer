"""Tests for Sentinel/KQL field extraction."""

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

    def test_extract_extend_fields(self):
        """Extract fields from extend operator."""
        query = 'SecurityEvent | extend AccountDomain = split(Account, "\\\\")[0]'
        result = extract_sentinel_fields(query)

        assert "AccountDomain" in result.fields_used


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
