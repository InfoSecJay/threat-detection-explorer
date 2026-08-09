"""Edge-case tests for ES|QL extraction.

Fills gaps in `test_esql_extractor.py`. Each test pins a real trap
pattern rather than aiming for line coverage. Where a test starts
failing, the fix lands in `extract_esql_fields` (services/field_extractor.py).
"""

from app.services.field_extractor import extract_esql_fields


class TestEsqlMultiTableFrom:
    """FROM supports multiple comma-separated tables in ES|QL."""

    def test_two_tables_both_captured(self):
        query = 'FROM logs-endpoint.events.process-*, logs-endpoint.events.file-*'
        result = extract_esql_fields(query)
        assert "logs-endpoint.events.process-*" in result.source_tables
        assert "logs-endpoint.events.file-*" in result.source_tables

    def test_three_tables_all_captured(self):
        query = 'FROM a-*, b-*, c-* | WHERE host.name == "x"'
        result = extract_esql_fields(query)
        assert set(["a-*", "b-*", "c-*"]).issubset(set(result.source_tables))


class TestEsqlComments:
    """`//` line comments and `/* */` block comments must not leak
    their contents into extracted observables."""

    def test_line_comment_not_extracted(self):
        query = '''
        FROM logs-*
        // WHERE process.name == "commented_out.exe"
        | WHERE event.action == "start"
        '''
        result = extract_esql_fields(query)
        # The commented-out process should NOT appear anywhere.
        assert "commented_out.exe" not in result.process_names
        # The real WHERE clause should still be extracted.
        assert any(o.field == "event.action" for o in result.observables)

    def test_block_comment_not_extracted(self):
        query = '''
        FROM logs-*
        /* WHERE process.name == "block_comment.exe" */
        | WHERE event.action == "start"
        '''
        result = extract_esql_fields(query)
        assert "block_comment.exe" not in result.process_names


class TestEsqlKeepAndDrop:
    """KEEP + DROP are field-selection pipe stages. Fields named there
    are examined by the rule and should show up in fields_used."""

    def test_keep_stage_populates_fields_used(self):
        query = '''
        FROM logs-*
        | WHERE event.action == "login"
        | KEEP user.name, source.ip, event.action
        '''
        result = extract_esql_fields(query)
        assert "user.name" in result.fields_used
        assert "source.ip" in result.fields_used

    def test_drop_stage_populates_fields_used(self):
        query = '''
        FROM logs-*
        | DROP internal.stuff, agent.type
        '''
        result = extract_esql_fields(query)
        assert "internal.stuff" in result.fields_used


class TestEsqlOrCondition:
    """OR-joined conditions should both surface as observables."""

    def test_or_captures_both_sides(self):
        query = '''
        FROM logs-*
        | WHERE process.name == "cmd.exe" OR process.name == "powershell.exe"
        '''
        result = extract_esql_fields(query)
        assert "cmd.exe" in result.process_names
        assert "powershell.exe" in result.process_names


class TestEsqlFunctionWrappedField:
    """`TO_LOWER(field) == "x"` should not extract `TO_LOWER(field)`
    as if it were a field name. The real field is inside."""

    def test_to_lower_wrapped_field_not_treated_as_field(self):
        query = '''
        FROM logs-*
        | WHERE TO_LOWER(process.name) == "cmd.exe"
        '''
        result = extract_esql_fields(query)
        # `TO_LOWER(process.name)` should NOT appear as a field.
        assert not any(o.field == "TO_LOWER(process.name)" for o in result.observables)
        # If we can pull the inner field, that's the win; if not,
        # at minimum we don't pollute with the wrapped form.
