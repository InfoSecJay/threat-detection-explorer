"""Tests for Sublime MQL field extraction."""

import pytest

from app.services.field_extractor import extract_sublime_fields


class TestSublimeExtractorBasic:
    """Basic Sublime MQL extraction tests."""

    def test_empty_query(self):
        result = extract_sublime_fields("")
        assert result.fields_used == []
        assert result.observables == []

    def test_equality_match(self):
        query = 'sender.email.domain == "evil.com"'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0
        assert any(o.field == "sender.email.domain" for o in result.observables)
        assert any("evil.com" in o.values for o in result.observables)

    def test_negated_equality(self):
        query = 'sender.email.domain != "trusted.com"'
        result = extract_sublime_fields(query)
        negated_obs = [o for o in result.observables if o.negated]
        assert len(negated_obs) > 0
        assert any("trusted.com" in o.values for o in negated_obs)

    def test_in_list(self):
        query = 'sender.email.domain in ("evil.com", "bad.org", "phish.net")'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0
        domain_obs = [o for o in result.observables if o.field == "sender.email.domain"]
        assert len(domain_obs) > 0
        assert len(domain_obs[0].values) == 3

    def test_regex_icontains(self):
        query = 'regex.icontains(sender.display_name, "paypal|microsoft|apple")'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0

    def test_strings_icontains(self):
        query = 'strings.icontains(body.current_thread.text, "verify your account")'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0

    def test_any_iterator(self):
        query = 'any(attachments, .file_name in ("invoice.pdf", "receipt.pdf"))'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0

    def test_source_table_type_inbound(self):
        query = 'type.inbound and sender.email.domain == "evil.com"'
        result = extract_sublime_fields(query)
        assert any("inbound" in st for st in result.source_tables)

    def test_source_table_type_outbound(self):
        query = 'type.outbound and recipients.to == "user@company.com"'
        result = extract_sublime_fields(query)
        assert any("outbound" in st for st in result.source_tables)


class TestSublimeEmailClassification:
    """Test that email-specific fields are correctly classified."""

    def test_sender_domain_classified(self):
        query = 'sender.email.domain.root_domain == "evil.com"'
        result = extract_sublime_fields(query)
        assert "sender.email.domain.root_domain" in result.fields_used

    def test_attachment_fields(self):
        query = 'any(attachments, .file_name == "malware.exe")'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0

    def test_body_urls(self):
        query = 'any(body.links, .href_url.domain.root_domain == "phishing.com")'
        result = extract_sublime_fields(query)
        assert len(result.observables) > 0


class TestSublimeComplexQueries:
    """Test more complex Sublime MQL patterns."""

    def test_complex_multi_condition(self):
        query = '''
        type.inbound
        and sender.email.domain != "trusted.com"
        and any(attachments, .file_extension in ("exe", "scr", "bat"))
        and regex.icontains(subject.subject, "urgent|invoice|payment")
        '''
        result = extract_sublime_fields(query)
        assert len(result.observables) >= 2
        assert any("inbound" in st for st in result.source_tables)

    def test_query_complexity_simple(self):
        query = 'sender.email.domain == "evil.com"'
        result = extract_sublime_fields(query)
        assert result.query_complexity == "simple"

    def test_query_complexity_not_unknown(self):
        query = '''
        type.inbound
        and sender.email.domain != "trusted.com"
        and any(attachments, .file_extension == "exe")
        and subject.subject == "Invoice"
        '''
        result = extract_sublime_fields(query)
        assert result.query_complexity in ("simple", "moderate", "complex")

    def test_fields_used_populated(self):
        query = '''
        sender.email.domain == "evil.com"
        and headers.return_path == "bounce@evil.com"
        '''
        result = extract_sublime_fields(query)
        assert "sender.email.domain" in result.fields_used
        assert "headers.return_path" in result.fields_used
