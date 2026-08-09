"""Edge-case tests for Sublime MQL extraction.

Same shape as the ES|QL edge-case suite. MQL is more forgiving syntax-
wise than ES|QL (fewer keywords, more function-like patterns), but the
trap classes are similar: comments, chained calls, variable references.
"""

from app.services.field_extractor import extract_sublime_fields


class TestSublimeComments:
    """MQL supports `//` line comments. Commented-out clauses must not
    contribute to observables."""

    def test_line_comment_not_extracted(self):
        query = '''
        type.inbound
        // and sender.email.domain.domain == "hidden.example.com"
        and any(recipients.to, .email.email == "victim@example.com")
        '''
        result = extract_sublime_fields(query)
        # Commented clause must not appear.
        assert "hidden.example.com" not in [
            v for o in result.observables for v in o.values
        ]
        # Real clause must still be there.
        assert "victim@example.com" in [
            v for o in result.observables for v in o.values
        ]


class TestSublimeVariableReferences:
    """MQL rules often use `$variable` references inside `in (...)` for
    shared lists (free email providers, allowlists). These are runtime
    values, not literals — the extractor must not crash or emit them
    as observables, and must still handle the containing rule."""

    def test_dollar_variable_in_list_no_crash(self):
        query = '''
        type.inbound
        and sender.email.domain.root_domain in $free_email_providers
        and subject.subject == "urgent invoice"
        '''
        # Must not raise.
        result = extract_sublime_fields(query)
        # $free_email_providers should NOT appear as a value.
        all_values = [v for o in result.observables for v in o.values]
        assert not any('$free_email_providers' in v for v in all_values)
        # The literal `subject == "urgent invoice"` must survive.
        assert 'urgent invoice' in all_values


class TestSublimeChainedAny:
    """`.attachments.any(...)` is a common MQL pattern — a method-style
    `any()` chained off a field reference. Distinct from top-level
    `any(field, .attr == "x")`. Both should populate observables."""

    def test_chained_any_captures_inner_field(self):
        query = '''
        type.inbound
        and any(attachments,
                .file_extension == "exe" and .size < 100000)
        '''
        result = extract_sublime_fields(query)
        # The inner `.file_extension == "exe"` should surface.
        all_values = [v for o in result.observables for v in o.values]
        assert "exe" in all_values


class TestSublimeNestedFieldPaths:
    """Long dotted field paths (>3 segments) are common in Sublime
    (`headers.mailer.name`, `sender.email.domain.root_domain`). They
    should extract cleanly."""

    def test_deep_dotted_path(self):
        query = 'sender.email.domain.root_domain == "malicious.top"'
        result = extract_sublime_fields(query)
        assert any(
            o.field == "sender.email.domain.root_domain" for o in result.observables
        )


class TestSublimeMultipleTypesAndOrs:
    """Complexity heuristic thresholds are AND/OR count-based. Verify
    a genuinely complex rule crosses into `complex`, not just `moderate`."""

    def test_many_conditions_reports_complex(self):
        # 9 boolean ops -> should hit `complex` (> 8)
        query = ' and '.join([f'field{i} == "v{i}"' for i in range(10)])
        result = extract_sublime_fields(query)
        assert result.query_complexity == "complex"

    def test_few_conditions_reports_simple(self):
        query = 'a == "x" and b == "y"'
        result = extract_sublime_fields(query)
        assert result.query_complexity == "simple"
