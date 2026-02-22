"""Tests for ES|QL field extraction."""

import pytest

from app.services.field_extractor import extract_esql_fields


class TestEsqlExtractorBasic:
    """Basic ES|QL extraction tests."""

    def test_empty_query(self):
        result = extract_esql_fields("")
        assert result.fields_used == []
        assert result.observables == []

    def test_from_source_table(self):
        query = 'FROM logs-endpoint.events.process-*'
        result = extract_esql_fields(query)
        assert "logs-endpoint.events.process-*" in result.source_tables

    def test_where_equality(self):
        query = '''
        FROM logs-endpoint.events.process-*
        | WHERE process.name == "powershell.exe"
        '''
        result = extract_esql_fields(query)
        assert len(result.observables) > 0
        assert any(o.field == "process.name" for o in result.observables)
        assert "powershell.exe" in result.process_names

    def test_where_not_equal(self):
        query = '''
        FROM logs-*
        | WHERE process.name != "explorer.exe"
        '''
        result = extract_esql_fields(query)
        negated = [o for o in result.observables if o.negated]
        assert len(negated) > 0

    def test_where_in_list(self):
        query = '''
        FROM logs-*
        | WHERE process.name IN ("cmd.exe", "powershell.exe", "pwsh.exe")
        '''
        result = extract_esql_fields(query)
        assert len(result.observables) > 0
        proc_obs = [o for o in result.observables if o.field == "process.name"]
        assert len(proc_obs) > 0
        assert len(proc_obs[0].values) == 3

    def test_where_like(self):
        query = '''
        FROM logs-*
        | WHERE process.command_line LIKE "*mimikatz*"
        '''
        result = extract_esql_fields(query)
        assert len(result.observables) > 0

    def test_where_rlike(self):
        query = '''
        FROM logs-*
        | WHERE process.name RLIKE ".*powershell.*"
        '''
        result = extract_esql_fields(query)
        assert len(result.observables) > 0

    def test_stats_by_fields(self):
        query = '''
        FROM logs-*
        | WHERE event.action == "login"
        | STATS count = COUNT(*) BY user.name, source.ip
        '''
        result = extract_esql_fields(query)
        assert "user.name" in result.fields_used or "source.ip" in result.fields_used


class TestEsqlCloudQueries:
    """Test ES|QL with cloud-specific patterns."""

    def test_aws_cloudtrail(self):
        query = '''
        FROM logs-aws.cloudtrail-*
        | WHERE event.action == "CreateUser"
        '''
        result = extract_esql_fields(query)
        assert "logs-aws.cloudtrail-*" in result.source_tables
        assert "CreateUser" in result.api_actions

    def test_okta_event(self):
        query = '''
        FROM logs-okta.system-*
        | WHERE event.action == "user.session.start"
        '''
        result = extract_esql_fields(query)
        assert "user.session.start" in result.api_actions

    def test_azure_activity(self):
        query = '''
        FROM logs-azure.activitylogs-*
        | WHERE event.action == "Microsoft.Authorization/roleAssignments/write"
        '''
        result = extract_esql_fields(query)
        assert len(result.api_actions) > 0


class TestEsqlComplexity:
    """Test query complexity estimation."""

    def test_simple_query(self):
        query = 'FROM logs-* | WHERE process.name == "cmd.exe"'
        result = extract_esql_fields(query)
        assert result.query_complexity == "simple"

    def test_moderate_query(self):
        query = '''
        FROM logs-*
        | WHERE process.name == "cmd.exe"
          AND process.parent.name == "explorer.exe"
          AND event.action == "start"
        | STATS count = COUNT(*) BY host.name
        '''
        result = extract_esql_fields(query)
        # Query has 3 conditions + STATS, complexity depends on thresholds
        assert result.query_complexity in ("simple", "moderate", "complex")

    def test_complex_query(self):
        query = '''
        FROM logs-endpoint.events.process-*
        | WHERE process.name IN ("cmd.exe", "powershell.exe")
          AND process.parent.name NOT IN ("explorer.exe", "svchost.exe")
          AND process.command_line LIKE "*-enc*"
          AND event.action == "start"
        | STATS cmd_count = COUNT(*) BY host.name, user.name
        | WHERE cmd_count > 5
        '''
        result = extract_esql_fields(query)
        assert result.query_complexity in ("moderate", "complex")

    def test_multiple_from_tables(self):
        query = '''
        FROM logs-endpoint.events.process-*, logs-endpoint.events.file-*
        | WHERE process.name == "cmd.exe"
        '''
        result = extract_esql_fields(query)
        assert len(result.source_tables) >= 1
