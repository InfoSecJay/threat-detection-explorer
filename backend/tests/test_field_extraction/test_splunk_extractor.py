"""Tests for Splunk SPL field extraction."""

import pytest
from app.services.field_extractor import extract_splunk_fields


class TestSplunkTstats:
    """Test tstats data model extraction."""

    def test_extract_datamodel_reference(self):
        """Extract data model from tstats query."""
        search = '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe by Processes.process Processes.process_name'
        result = extract_splunk_fields(search)

        assert "Endpoint.Processes" in result.source_tables
        assert "Processes.process_name" in result.fields_used
        assert "powershell.exe" in result.process_names

    def test_extract_tstats_parent_process(self):
        """Extract parent process from tstats."""
        search = '| tstats count from datamodel=Endpoint.Processes where Processes.parent_process_name=hh.exe by Processes.process_name Processes.dest'
        result = extract_splunk_fields(search)

        assert "Endpoint.Processes" in result.source_tables
        assert "Processes.parent_process_name" in result.fields_used
        assert "hh.exe" in result.process_names

    def test_extract_tstats_by_fields(self):
        """Extract fields from 'by' clause."""
        search = '| tstats count from datamodel=Endpoint.Processes by Processes.process_name, Processes.dest, Processes.user'
        result = extract_splunk_fields(search)

        assert "Processes.dest" in result.fields_used or "Processes.user" in result.fields_used


class TestSplunkIndexSourcetype:
    """Test index and sourcetype extraction."""

    def test_extract_index_and_eventcode(self):
        """Extract index and EventCode."""
        search = 'index=wineventlog sourcetype=WinEventLog:Security EventCode=4688'
        result = extract_splunk_fields(search)

        assert "wineventlog" in result.source_tables
        assert "4688" in result.event_ids

    def test_extract_eventcode_in_list(self):
        """Extract EventCode from IN operator."""
        search = 'index=main EventCode IN (4688, 4689, 1)'
        result = extract_splunk_fields(search)

        assert "4688" in result.event_ids
        assert "4689" in result.event_ids
        assert "1" in result.event_ids

    def test_extract_sourcetype(self):
        """Extract sourcetype."""
        search = 'index=main sourcetype=WinEventLog:Security'
        result = extract_splunk_fields(search)

        assert "WinEventLog:Security" in result.source_tables


class TestSplunkWhereClause:
    """Test where clause extraction."""

    def test_extract_where_in(self):
        """Extract fields from where IN clause."""
        search = '| tstats count from datamodel=Endpoint.Processes | where process_name IN ("cmd.exe", "powershell.exe")'
        result = extract_splunk_fields(search)

        assert "process_name" in result.fields_used
        assert "cmd.exe" in result.process_names
        assert "powershell.exe" in result.process_names


class TestSplunkMessageId:
    """Test message_id / EventCode extraction."""

    def test_extract_message_id_in(self):
        """Extract message_id from IN operator."""
        search = '`cisco_asa` message_id IN (111008, 111010)'
        result = extract_splunk_fields(search)

        assert "111008" in result.event_ids
        assert "111010" in result.event_ids


class TestSplunkComplexity:
    """Test query complexity assessment."""

    def test_simple_search(self):
        search = 'index=main EventCode=4688'
        result = extract_splunk_fields(search)
        assert result.query_complexity == "simple"

    def test_moderate_piped(self):
        search = 'index=main | stats count by process_name | where count > 10 | sort -count'
        result = extract_splunk_fields(search)
        assert result.query_complexity == "moderate"

    def test_complex_join(self):
        search = 'index=main | join type=inner dest [search index=threat_intel | fields dest, threat_score]'
        result = extract_splunk_fields(search)
        assert result.query_complexity == "complex"

    def test_complex_transaction(self):
        search = 'index=main | transaction host maxspan=30s startswith="login" endswith="logout"'
        result = extract_splunk_fields(search)
        assert result.query_complexity == "complex"


class TestSplunkStatsByFields:
    """Test stats by field extraction."""

    def test_extract_stats_by_fields(self):
        """Extract field names from stats by clause."""
        search = '| tstats count from datamodel=Endpoint.Processes | stats count by process_name, dest'
        result = extract_splunk_fields(search)

        # process_name and dest should appear in fields_used
        assert any("process_name" in f for f in result.fields_used)
        assert any("dest" in f for f in result.fields_used)


class TestSplunkRebuildFixture:
    """Issue #6 rebuild fixture — real ESCU shapes pinning the FP
    classes the 2026-08-26 baseline audit measured (2,066 unsplit
    field lists, wildcard noise, alias pollution)."""

    def test_space_separated_by_list_is_split(self):
        # THE dominant junk class: ESCU by-lists are space-separated.
        search = (
            '| tstats `security_content_summariesonly` count from '
            'datamodel=Endpoint.Processes where Processes.process_name="arp.exe" '
            'by Processes.action Processes.dest Processes.parent_process_name '
            'Processes.process_id Processes.user'
        )
        result = extract_splunk_fields(search)
        for f in (
            "Processes.action", "Processes.dest",
            "Processes.parent_process_name", "Processes.process_id",
            "Processes.user",
        ):
            assert f in result.fields_used, f
        # No unsplit multi-field strings.
        assert not any(" " in f for f in result.fields_used)

    def test_stats_aggregation_args_yes_aliases_no(self):
        search = (
            '| stats count earliest(_time) as firstTime latest(_time) as lastTime '
            'values(user) as user_list values(command) as command_list by host'
        )
        result = extract_splunk_fields(search)
        assert "user" in result.fields_used
        assert "command" in result.fields_used
        assert "host" in result.fields_used
        # `as` aliases are derived, not telemetry fields.
        assert "firstTime" not in result.fields_used
        assert "lastTime" not in result.fields_used
        assert "user_list" not in result.fields_used

    def test_triple_backtick_comments_are_ignored(self):
        search = (
            '| `cisco_ai_defense` ```Aggregating data by model name, '
            'connection name``` | stats count by application_name'
        )
        result = extract_splunk_fields(search)
        assert "application_name" in result.fields_used
        assert not any("Aggregating" in f for f in result.fields_used)

    def test_eval_targets_are_derived_not_fields(self):
        search = (
            '| eval msg_desc=case(message_id="302013","Built inbound") '
            '| stats count values(msg_desc) as message_description by message_id'
        )
        result = extract_splunk_fields(search)
        assert "msg_desc" not in result.fields_used
        assert "message_id" in result.fields_used

    def test_fields_and_table_commands(self):
        result = extract_splunk_fields(
            'index=main | fields dest user process_id | table dest, user'
        )
        assert "dest" in result.fields_used
        assert "user" in result.fields_used
        assert "process_id" in result.fields_used
        # Removal lists reference fields being DROPPED.
        result2 = extract_splunk_fields('index=main | fields - _raw punct')
        assert "_raw" not in result2.fields_used
        assert "punct" not in result2.fields_used

    def test_rename_source_field_kept_alias_excluded(self):
        result = extract_splunk_fields(
            '| `cloudtrail` | rename userIdentity.accountId as vendor_account '
            '| stats count by vendor_account'
        )
        assert "userIdentity.accountId" in result.fields_used
        # vendor_account only exists post-rename — derived everywhere.
        assert "vendor_account" not in result.fields_used

    def test_subsearch_pipeline_is_extracted(self):
        search = (
            'index=main | join type=inner dest '
            '[search index=threat_intel | fields dest threat_score]'
        )
        result = extract_splunk_fields(search)
        assert "threat_intel" in result.source_tables
        assert "threat_score" in result.fields_used

    def test_wildcard_only_value_records_field_without_noise(self):
        search = (
            '| tstats count from datamodel=Endpoint.Processes '
            'where Processes.process=* by Processes.dest'
        )
        result = extract_splunk_fields(search)
        assert "Processes.process" in result.fields_used
        # "*" is match-anything syntax, not an observable value.
        assert not any(
            "*" in (o.values or [""])[0] and len(o.values[0]) == 1
            for o in result.observables
        )

    def test_event_ids_numeric_only(self):
        result = extract_splunk_fields(
            '`cloudtrail` eventName=ConsoleLogin errorCode=success '
            '| search signature_id=4625'
        )
        assert "4625" in result.event_ids
        assert "success" not in result.event_ids
        assert "ConsoleLogin" not in result.event_ids

    def test_file_paths_require_a_separator(self):
        result = extract_splunk_fields(
            'index=main Filesystem.file_path IN ("*.dat", "C:\\\\Temp\\\\x.dll")'
        )
        assert "C:\\\\Temp\\\\x.dll" in result.file_paths
        assert "*.dat" not in result.file_paths

    def test_bare_value_trailing_paren_is_trimmed(self):
        search = (
            '| tstats count from datamodel=Endpoint.Processes '
            'where (Processes.process_name="arp.exe") (Processes.process=*-a*) '
            'by Processes.dest'
        )
        result = extract_splunk_fields(search)
        vals = [v for o in result.observables for v in o.values]
        assert "*-a*" in vals
        assert "*-a*)" not in vals

    def test_negated_comparison_is_marked(self):
        result = extract_splunk_fields(
            '`cloudtrail` userAgent!=console.amazonaws.com'
        )
        neg = [o for o in result.observables if o.field == "userAgent"]
        assert neg and neg[0].negated


class TestSplunkEdgeCases:
    """Test edge cases."""

    def test_empty_search(self):
        result = extract_splunk_fields("")
        assert result.fields_used == []

    def test_none_search(self):
        result = extract_splunk_fields(None)
        assert result.fields_used == []

    def test_macro_present(self):
        """Macros in backticks should not break extraction."""
        search = '`sysmon` EventCode=1 CommandLine="*certutil*"'
        result = extract_splunk_fields(search)

        assert "1" in result.event_ids

    def test_complex_real_world_spl(self):
        """Test with realistic Splunk ESCU detection."""
        search = '''| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=hh.exe by Processes.action Processes.dest Processes.process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `detect_html_help_spawn_child_process_filter`'''
        result = extract_splunk_fields(search)

        assert "Endpoint.Processes" in result.source_tables
        assert "Processes.parent_process_name" in result.fields_used
        assert "hh.exe" in result.process_names
