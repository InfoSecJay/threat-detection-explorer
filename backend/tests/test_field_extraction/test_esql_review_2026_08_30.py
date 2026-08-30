"""ES|QL semantic review fixture (2026-08-30).

Each case is a pattern reproduced from production Elastic hunting
rules. The extractor ran identifier regexes over unmasked text, so
string literals leaked into fields_used, `/* */` stripping ate the
text between two `"/x/*"` literals, `//` inside a URL literal
truncated the WHERE clause, `FROM ... METADATA _id, _version` put the
metadata columns into source_tables, and starts_with / ends_with /
cidr_match / the `:` match operator produced no observables at all.
"""

from app.services.field_extractor import extract_esql_fields


def _obs(result, field_name):
    return [o for o in result.observables if o.field == field_name]


class TestLiteralsDoNotLeakIntoFieldsUsed:
    def test_in_list_and_equality_literals_stay_out_of_fields_used(self):
        q = '''
        from logs-aws.cloudtrail*
        | where event.dataset == "aws.cloudtrail"
          and process.name in ("powershell.exe", "rundll32.exe")
          and process.parent.name == "svchost.exe"
        '''
        r = extract_esql_fields(q)
        assert set(r.fields_used) == {
            "event.dataset", "process.name", "process.parent.name",
        }
        # Observables keep the literals; only fields_used is cleaned.
        assert _obs(r, "process.name")[0].values == ["powershell.exe", "rundll32.exe"]
        assert "powershell.exe" in r.process_names
        assert r.source_tables == ["logs-aws.cloudtrail*"]

    def test_dotted_literals_in_eval_do_not_leak(self):
        q = '''
        from logs-okta.system*
        | eval Esql.src = coalesce(client.ip, "ec2.amazonaws.com")
        | where event.dataset == "okta.system" and user.name != "dispatcher.d"
        '''
        r = extract_esql_fields(q)
        assert set(r.fields_used) == {"client.ip", "event.dataset", "user.name"}
        assert _obs(r, "user.name")[0].negated is True

    def test_triple_quoted_literal(self):
        q = '''
        from logs-endpoint.events.process-*
        | where process.command_line like """*signin.amazonaws.com/*""" and process.name == "curl"
        '''
        r = extract_esql_fields(q)
        assert set(r.fields_used) == {"process.command_line", "process.name"}
        assert _obs(r, "process.command_line")[0].values == ["*signin.amazonaws.com/*"]

    def test_pipe_inside_literal_does_not_split_stage(self):
        q = '''
        from logs-*
        | where process.command_line like "*a|b*"
        | stats c = count() by host.name
        '''
        r = extract_esql_fields(q)
        assert _obs(r, "process.command_line")[0].values == ["*a|b*"]
        assert "host.name" in r.fields_used


class TestCommentStrippingIsQuoteAware:
    def test_two_glob_literals_are_not_merged_as_a_block_comment(self):
        q = '''
        from logs-endpoint.events.file-*
        | where file.path like "/usr/share/dbus-1/*" or file.path like "/home/*/.local/share/dbus-1/*"
        '''
        r = extract_esql_fields(q)
        values = [v for o in _obs(r, "file.path") for v in o.values]
        assert values == ["/usr/share/dbus-1/*", "/home/*/.local/share/dbus-1/*"]
        assert r.file_paths == ["/usr/share/dbus-1/*", "/home/*/.local/share/dbus-1/*"]

    def test_double_slash_inside_literal_is_not_a_line_comment(self):
        q = '''
        from logs-*
        | where url.full == "http://a.b//c" and process.name == "curl"
        '''
        r = extract_esql_fields(q)
        assert _obs(r, "url.full")[0].values == ["http://a.b//c"]
        assert "http://a.b//c" in r.network_indicators
        assert "curl" in r.process_names

    def test_real_comments_are_still_stripped(self):
        q = '''
        from logs-*
        // where process.name == "commented.exe"
        | where file.path like "/tmp/*" /* process.name == "block.exe" */ and process.name == "sh"
        '''
        r = extract_esql_fields(q)
        assert "commented.exe" not in r.process_names
        assert "block.exe" not in r.process_names
        assert r.process_names == ["sh"]
        assert _obs(r, "file.path")[0].values == ["/tmp/*"]


class TestFromMetadata:
    def test_metadata_columns_are_not_source_tables(self):
        q = '''
        from logs-windows.powershell_operational* metadata _id, _version, _index
        | where powershell.file.script_block_text : "char"
        '''
        r = extract_esql_fields(q)
        assert r.source_tables == ["logs-windows.powershell_operational*"]
        assert "_version" not in r.fields_used
        assert "_index" not in r.fields_used

    def test_metadata_with_multiple_tables(self):
        q = 'from a-*, b-* METADATA _id | where host.name == "x"'
        r = extract_esql_fields(q)
        assert r.source_tables == ["a-*", "b-*"]


class TestFunctionPredicates:
    def test_starts_with_registry_path(self):
        q = r'''
        from logs-endpoint.events.registry-*
        | where starts_with(registry.path, "HKLM\\SYSTEM\\CurrentControlSet\\")
        '''
        r = extract_esql_fields(q)
        obs = _obs(r, "registry.path")
        assert len(obs) == 1
        # Literal body is kept as written in the query (no unescaping),
        # matching how == values are stored.
        assert obs[0].values == ["HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\"]
        assert obs[0].negated is False
        assert r.registry_keys == ["HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\"]
        assert r.fields_used == ["registry.path"]

    def test_ends_with_process_name(self):
        q = '''
        from logs-*
        | where ends_with(process.name, ".exe") and process.parent.name == "explorer.exe"
        '''
        r = extract_esql_fields(q)
        obs = _obs(r, "process.name")
        assert obs and obs[0].values == [".exe"]
        assert ".exe" not in r.fields_used
        assert "explorer.exe" in r.process_names

    def test_cidr_match_populates_network_indicators(self):
        q = '''
        from logs-*
        | where cidr_match(source.ip, "10.0.0.0/8", "192.168.0.0/16")
        '''
        r = extract_esql_fields(q)
        obs = _obs(r, "source.ip")
        assert obs and obs[0].values == ["10.0.0.0/8", "192.168.0.0/16"]
        assert r.network_indicators == ["10.0.0.0/8", "192.168.0.0/16"]
        assert r.fields_used == ["source.ip"]

    def test_not_starts_with_is_negated(self):
        q = '''
        from logs-*
        | where not starts_with(process.executable, "C:\\\\Windows\\\\") and NOT cidr_match(source.ip, "10.0.0.0/8")
        '''
        r = extract_esql_fields(q)
        assert _obs(r, "process.executable")[0].negated is True
        assert _obs(r, "source.ip")[0].negated is True

    def test_not_in_is_negated(self):
        q = '''
        from logs-*
        | where process.parent.name not in ("explorer.exe", "svchost.exe")
        '''
        r = extract_esql_fields(q)
        obs = _obs(r, "process.parent.name")
        assert obs and obs[0].negated is True
        assert obs[0].values == ["explorer.exe", "svchost.exe"]


class TestMatchOperator:
    def test_colon_reads_like_equality(self):
        q = '''
        from logs-windows.powershell_operational*
        | where powershell.file.script_block_text : "char" and process.name : "powershell.exe"
        '''
        r = extract_esql_fields(q)
        obs = _obs(r, "powershell.file.script_block_text")
        assert obs and obs[0].values == ["char"] and obs[0].negated is False
        assert "powershell.exe" in r.process_names
        assert "char" not in r.fields_used

    def test_cast_suffix_is_not_a_field(self):
        q = 'from logs-* | where event.code::keyword == "4688"'
        r = extract_esql_fields(q)
        assert "keyword" not in [o.field for o in r.observables]


class TestDerivedCapturesSurviveMasking:
    def test_dissect_pattern_captures_are_still_derived(self):
        q = '''
        from logs-*
        | dissect message "%{Esql.user} logged in from %{src.ip}"
        | where src.ip is not null
        '''
        r = extract_esql_fields(q)
        assert "message" in r.fields_used
        assert "src.ip" not in r.fields_used
