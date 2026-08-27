"""Tests for Sublime MQL field extraction."""

import pytest

from app.services.field_extractor import extract_sublime_fields


class TestMqlScopeResolution:
    """Issue #6 rebuild fixture — relative fields resolve against their
    iterator container; leading-dot junk (3,092 baseline entries) is
    structurally impossible."""

    def test_any_relative_field_resolves_to_container_path(self):
        r = extract_sublime_fields(
            "any(body.links, strings.icontains(.display_text, 'Go to File'))"
        )
        assert "body.links.display_text" in r.fields_used
        obs = [o for o in r.observables if o.field == "body.links.display_text"]
        assert obs and obs[0].values == ["Go to File"]
        assert obs[0].type == "email" and obs[0].subtype == "url"

    def test_nested_filter_container_resolves(self):
        r = extract_sublime_fields(
            'any(filter(body.links, (.href_url.domain.domain == "app.box.com")), '
            ".display_text == 'x')"
        )
        assert "body.links.href_url.domain.domain" in r.fields_used
        assert "app.box.com" in r.network_indicators

    def test_no_leading_dot_fields_survive(self):
        r = extract_sublime_fields(
            'any(attachments, .file_extension in ("pdf", "docx"))\n'
            "and any(body.links, regex.icontains(.display_text, 'foo'))"
        )
        assert all(not f.startswith(".") for f in r.fields_used)
        assert "attachments.file_extension" in r.fields_used

    def test_postfix_attribute_access_is_not_scope_mangled(self):
        # `.intents` after a call result is attribute access, and the
        # inner relative fields resolve against the full chain.
        r = extract_sublime_fields(
            "any(ml.nlu_classifier(body.current_thread.text).intents, "
            '.name == "cred_theft" and .confidence == "high")'
        )
        assert "ml.nlu_classifier.intents.name" in r.fields_used
        assert "ml.nlu_classifier.intents.confidence" in r.fields_used
        assert not any("classifierintents" in f for f in r.fields_used)

    def test_bare_dot_argument_is_the_element(self):
        r = extract_sublime_fields(
            "any(body.links, ml.link_analysis(., mode=\"aggressive\")"
            '.credphish.disposition == "phishing")'
        )
        # The disposition comparison is captured with a sane field name.
        assert any("credphish.disposition" in f for f in r.fields_used)
        assert all(not f.startswith(".") for f in r.fields_used)

    def test_single_quoted_values_and_named_lists(self):
        r = extract_sublime_fields(
            "strings.icontains(subject.subject, 'invited you to')\n"
            "and sender.email.domain.domain in $org_domains"
        )
        subj = [o for o in r.observables if o.field == "subject.subject"]
        assert subj and subj[0].values == ["invited you to"]
        # $list content isn't in the rule, but the field reference is.
        assert "sender.email.domain.domain" in r.fields_used

    def test_unquoted_comparisons_record_field_only(self):
        r = extract_sublime_fields(
            "headers.auth_summary.spf.pass == false and length(recipients.to) >= 4"
        )
        assert "headers.auth_summary.spf.pass" in r.fields_used
        assert not any(
            o.field == "headers.auth_summary.spf.pass" for o in r.observables
        )

    def test_regex_patterns_stay_off_the_indicator_surface(self):
        r = extract_sublime_fields(
            "any(body.links, regex.icontains(.href_url.path, "
            "'\\b(fund|portfolio|agreement) and more\\b'))"
        )
        obs = [o for o in r.observables if "href_url.path" in o.field]
        assert obs  # pattern kept on the observable...
        assert all(" " not in v for v in r.network_indicators)  # ...not as an indicator


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
