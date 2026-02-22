"""Tests for Elastic field extraction (EQL, KQL, Lucene)."""

import pytest
from app.services.field_extractor import extract_elastic_fields


class TestEQLProcessFields:
    """Test EQL process event extraction."""

    def test_extract_process_name_eq(self):
        """Extract process name from == comparison."""
        query = 'process where process.name == "powershell.exe" and process.args : "-enc"'
        result = extract_elastic_fields(query, "eql")

        assert "process.name" in result.fields_used
        assert "process.args" in result.fields_used
        assert "powershell.exe" in result.process_names
        assert "process" in result.source_tables

    def test_extract_process_in_list(self):
        """Extract process names from IN operator."""
        query = '''process where process.name in ("cmd.exe", "powershell.exe", "wscript.exe")'''
        result = extract_elastic_fields(query, "eql")

        assert "process.name" in result.fields_used
        assert "cmd.exe" in result.process_names
        assert "powershell.exe" in result.process_names
        assert "wscript.exe" in result.process_names

    def test_extract_parent_process(self):
        """Extract parent process fields."""
        query = 'process where process.parent.name in ("node", "node.exe") and process.name == "cmd.exe"'
        result = extract_elastic_fields(query, "eql")

        assert "process.parent.name" in result.fields_used
        assert "process.name" in result.fields_used
        assert "cmd.exe" in result.process_names


class TestEQLSequence:
    """Test EQL sequence extraction."""

    def test_sequence_complexity(self):
        """Sequences should be marked as complex."""
        query = '''
        sequence by host.name with maxspan=30s
          [process where process.name == "mshta.exe"]
          [network where destination.port == 443]
        '''
        result = extract_elastic_fields(query, "eql")

        assert result.query_complexity == "complex"
        assert "process.name" in result.fields_used
        assert "destination.port" in result.fields_used
        assert "mshta.exe" in result.process_names
        assert "443" in result.network_indicators

    def test_sequence_extracts_all_events(self):
        """Fields from all events in sequence should be extracted."""
        query = '''
        sequence by user.name with maxspan=5m
          [process where process.name == "cmd.exe"]
          [file where file.path : "C:\\\\Windows\\\\Temp\\\\*"]
        '''
        result = extract_elastic_fields(query, "eql")

        assert "process.name" in result.fields_used
        assert "file.path" in result.fields_used
        assert "cmd.exe" in result.process_names


class TestEQLNegation:
    """Test negated conditions in EQL."""

    def test_not_equals(self):
        """Extract negated fields from != operator."""
        query = 'process where process.name == "cmd.exe" and process.parent.name != "explorer.exe"'
        result = extract_elastic_fields(query, "eql")

        negated = [o for o in result.observables if o.negated]
        assert len(negated) == 1
        assert negated[0].field == "process.parent.name"


class TestEQLLikePattern:
    """Test EQL like/like~ pattern matching."""

    def test_like_tilde_pattern(self):
        """Extract from like~ operator."""
        query = 'process where process.command_line like~ ("*curl*http*", "*wget*http*")'
        result = extract_elastic_fields(query, "eql")

        assert "process.command_line" in result.fields_used
        obs = [o for o in result.observables if o.field == "process.command_line"]
        assert len(obs) > 0


class TestEQLNetworkFields:
    """Test network field extraction from EQL."""

    def test_extract_network_fields(self):
        """Extract network event fields."""
        query = 'network where destination.ip == "10.0.0.1" and destination.port == 443'
        result = extract_elastic_fields(query, "eql")

        assert "destination.ip" in result.fields_used
        assert "destination.port" in result.fields_used
        assert "10.0.0.1" in result.network_indicators
        assert "443" in result.network_indicators

    def test_extract_dns_fields(self):
        """Extract DNS fields."""
        query = 'dns where dns.question.name : "*.evil.com"'
        result = extract_elastic_fields(query, "eql")

        assert "dns.question.name" in result.fields_used
        assert "*.evil.com" in result.network_indicators


class TestEQLRegistryFields:
    """Test registry field extraction from EQL."""

    def test_extract_registry_path(self):
        """Extract registry paths."""
        query = 'registry where registry.path : "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*"'
        result = extract_elastic_fields(query, "eql")

        assert "registry.path" in result.fields_used
        assert len(result.registry_keys) > 0


class TestElasticKQL:
    """Test Elastic KQL (Kuery) extraction."""

    def test_extract_kql_field_value(self):
        """Extract field:value from KQL."""
        query = 'process.name: "powershell.exe" and process.args: ("-enc" or "-nop")'
        result = extract_elastic_fields(query, "kql")

        assert "process.name" in result.fields_used
        assert "process.args" in result.fields_used
        assert "powershell.exe" in result.process_names

    def test_extract_kql_simple(self):
        """Extract from simple KQL."""
        query = 'http.response.status_code:403 and http.request.method:post'
        result = extract_elastic_fields(query, "kql")

        assert "http.response.status_code" in result.fields_used
        assert "http.request.method" in result.fields_used

    def test_kql_complexity(self):
        """Simple KQL should be marked simple."""
        query = 'process.name:"cmd.exe"'
        result = extract_elastic_fields(query, "kql")
        assert result.query_complexity == "simple"


class TestLucene:
    """Test Lucene query extraction."""

    def test_extract_lucene_fields(self):
        """Extract from Lucene field:value syntax."""
        query = 'process.name:"mimikatz.exe" AND event.action:"start"'
        result = extract_elastic_fields(query, "lucene")

        assert "process.name" in result.fields_used
        assert "mimikatz.exe" in result.process_names

    def test_extract_lucene_parens(self):
        """Extract from Lucene with parenthesized values."""
        query = 'process.name:("cmd.exe" OR "powershell.exe")'
        result = extract_elastic_fields(query, "lucene")

        assert "cmd.exe" in result.process_names
        assert "powershell.exe" in result.process_names


class TestElasticEdgeCases:
    """Test edge cases."""

    def test_empty_query(self):
        result = extract_elastic_fields("", "eql")
        assert result.fields_used == []

    def test_none_query(self):
        result = extract_elastic_fields(None, "eql")
        assert result.fields_used == []

    def test_auto_detect_eql(self):
        """Auto-detect EQL from query syntax."""
        query = 'process where process.name == "test.exe"'
        result = extract_elastic_fields(query, "unknown")
        assert "process.name" in result.fields_used

    def test_file_event_extraction(self):
        """Extract file fields from EQL file events."""
        query = 'file where file.name : "malware.exe" and file.path : "C:\\\\Users\\\\*"'
        result = extract_elastic_fields(query, "eql")

        assert "file.name" in result.fields_used
        assert "file.path" in result.fields_used
        assert "file" in result.source_tables
