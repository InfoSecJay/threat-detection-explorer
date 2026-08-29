"""Precision fixes from the 2026-08-29 production extraction audit (#6).

Each test pins a failure seen on live rules re-run through master:
  - Elastic KQL/Lucene: `field : value` matched inside quoted strings
    (`"C:\\Program Files\\..."` -> bogus `C` field), no negation.
  - Elastic ML rules: synthesized "Machine Learning Job:" text yielded
    a `Job` field.
  - Sublime MQL: `//` inside a string literal was stripped as a comment
    (`'//title'`), corrupting scope resolution for the rest of the rule;
    `class="..."` inside a regex literal became a field; `.field` after
    an index (`hops[0].received`) lost its dot.
  - Empty string values produced observables.
  - Vocabulary: Auth0 / Sentinel / Splunk / Sigma RPC fields that were
    `other/unknown`.
"""

from app.services.field_extractor import (
    _classify_field,
    extract_elastic_fields,
    extract_sublime_fields,
)


def _obs(result, field):
    return [o for o in result.observables if o.field == field]


def _values(result):
    return {v for o in result.observables for v in o.values}


# -- Elastic KQL / Lucene -----------------------------------------------------


class TestKqlTokenizer:
    def test_colon_inside_quoted_path_is_not_a_field(self):
        q = (
            'process.name : "msbuild.exe" and not process.executable : ('
            '"C:\\\\Program Files\\\\Microsoft Visual Studio\\\\2022\\\\MSBuild.exe" or '
            '"C:\\\\Program Files (x86)\\\\Microsoft Visual Studio\\\\2019\\\\MSBuild.exe")'
        )
        r = extract_elastic_fields(q, "kql")
        assert "C" not in r.fields_used
        assert r.fields_used == ["process.name", "process.executable"]
        exe = _obs(r, "process.executable")[0]
        assert exe.negated is True
        assert len(exe.values) == 2
        assert all(v.startswith("C:\\\\Program Files") for v in exe.values)

    def test_not_group_negates_every_term_inside(self):
        r = extract_elastic_fields('event.category : "process" and not (user.name : "SYSTEM" or user.name : "root")', "kql")
        names = _obs(r, "user.name")
        assert len(names) == 2 and all(o.negated for o in names)
        assert _obs(r, "event.category")[0].negated is False

    def test_bare_and_wildcard_values(self):
        r = extract_elastic_fields("host.os.type : windows and process.name : *.exe and dns.question.name : example.com", "kql")
        assert _values(r) == {"windows", "*.exe", "example.com"}

    def test_group_of_bare_tokens(self):
        r = extract_elastic_fields("event.action : (start or creation) and user.id : (0 or 500)", "kql")
        assert _obs(r, "event.action")[0].values == ["start", "creation"]
        assert _obs(r, "user.id")[0].values == ["0", "500"]

    def test_single_quoted_value_with_colon(self):
        r = extract_elastic_fields("url.full : 'https://evil.example:8443/x' and http.request.method : POST", "kql")
        assert _obs(r, "url.full")[0].values == ["https://evil.example:8443/x"]
        assert "https" not in r.fields_used

    def test_lucene_uses_same_scanner(self):
        r = extract_elastic_fields('process.name:("cmd.exe" OR "pwsh.exe") AND NOT user.name:"admin"', "lucene")
        assert _obs(r, "process.name")[0].values == ["cmd.exe", "pwsh.exe"]
        assert _obs(r, "user.name")[0].negated is True

    def test_comparison_operators_are_not_colon_terms(self):
        r = extract_elastic_fields("process.args_count >= 3 and process.name : \"x.exe\"", "kql")
        assert r.fields_used == ["process.name"]


def test_ml_rules_yield_nothing():
    r = extract_elastic_fields("Machine Learning Job: ['v3_windows_anomalous_service_ea']", "ml")
    assert r.fields_used == [] and r.observables == []


# -- Sublime MQL -------------------------------------------------------------


class TestMqlLiteralSafety:
    def test_double_slash_inside_string_is_not_a_comment(self):
        q = """
        type.inbound
        and any(html.xpath(body.html, '//title').nodes,
                strings.icontains(.inner_text, 'Social Security'))
        and any(ml.nlu_classifier(body.current_thread.text).entities,
                .name == "sender" and .text == "SSA")
        """
        r = extract_sublime_fields(q)
        assert "inner_text" not in r.fields_used
        assert "name" not in r.fields_used
        assert "ml.nlu_classifier.entities.name" in r.fields_used
        assert "ml.nlu_classifier.entities.text" in r.fields_used
        assert "html.xpath.nodes.inner_text" in r.fields_used
        assert {"sender", "SSA", "Social Security"} <= _values(r)

    def test_real_comment_still_stripped(self):
        q = """
        type.inbound
        // and sender.email.domain.domain == "hidden.example.com"
        and sender.email.domain.domain == "seen.example.com"
        """
        r = extract_sublime_fields(q)
        assert _values(r) == {"seen.example.com"}

    def test_field_equals_inside_regex_literal_is_ignored(self):
        q = """
        type.inbound
        and regex.icontains(body.html.raw, '(<p class=".*?"><span style=".*?"><o:p>&nbsp;</o:p></span></p>\\s*){30,}')
        """
        r = extract_sublime_fields(q)
        assert "class" not in r.fields_used and "style" not in r.fields_used
        assert "body.html.raw" in r.fields_used
        body = _obs(r, "body.html.raw")[0]
        assert body.values[0].startswith("(<p class=")

    def test_index_postfix_keeps_full_path(self):
        q = 'type.inbound and headers.hops[0].received.server.raw == "relay.mimecast.com"'
        r = extract_sublime_fields(q)
        assert "received.server.raw" not in r.fields_used
        assert any(f.endswith("received.server.raw") and f.startswith("headers.hops") for f in r.fields_used)
        assert "relay.mimecast.com" in _values(r)

    def test_empty_string_value_is_a_field_ref_not_an_observable(self):
        r = extract_sublime_fields('type.inbound and sender.email.domain.domain == ""')
        assert "sender.email.domain.domain" in r.fields_used
        assert _obs(r, "sender.email.domain.domain") == []


# -- Vocabulary ----------------------------------------------------------------


class TestVocabularyPass:
    def test_auth0_fields(self):
        assert _classify_field("data.type") == ("identity", "action")
        assert _classify_field("data.tenant_name") == ("identity", "context")
        assert _classify_field("data.description") == ("event", "message")

    def test_sigma_rpc_firewall(self):
        assert _classify_field("endpoint") == ("network", "protocol")
        assert _classify_field("operation") == ("cloud", "api_action")

    def test_sentinel_generic_columns(self):
        assert _classify_field("DataSource") == ("event", "event_source")
        assert _classify_field("EventResult") == ("cloud", "result")
        assert _classify_field("IpAddress") == ("network", "ip_address")

    def test_free_text_is_message_not_unknown(self):
        for f in ("Message", "Description", "ResultDescription", "additional.fields.msg_1"):
            assert _classify_field(f) == ("event", "message"), f

    def test_elastic_and_panther(self):
        assert _classify_field("http.request.body.content") == ("network", "http_body")
        assert _classify_field("kubernetes.audit.user.username") == ("cloud", "principal")
        assert _classify_field("event_simplename") == ("event", "event_category")
        assert _classify_field("userIdentity.invokedBy") == ("cloud", "principal")


class TestMqlListContainers:
    def test_list_of_transformed_fields_resolves_to_the_field(self):
        q = """
        type.inbound
        and any([
              strings.replace_confusables(sender.display_name),
              strings.replace_confusables(subject.subject),
              sender.email.local_part
            ],
            strings.icontains(., "Capital One")
            or regex.icontains(., 'Capital.?One')
        )
        """
        r = extract_sublime_fields(q)
        assert "strings.replace_confusables" not in r.fields_used
        assert "sender.display_name" in r.fields_used
        assert {"Capital One", "Capital.?One"} <= _values(r)

    def test_call_with_postfix_still_collapses_parens(self):
        q = 'type.inbound and any(ml.nlu_classifier(body.current_thread.text).intents, .name == "bec")'
        r = extract_sublime_fields(q)
        assert "ml.nlu_classifier.intents.name" in r.fields_used


class TestNetworkIndicatorContract:
    def test_only_ips_domains_and_urls_reach_the_indicator_surface(self):
        from app.services.field_extractor import _is_network_indicator as ok
        keep = ["10.0.0.1", "192.168.0.0/16", "2001:db8::1", "evil.example.com", "*.anonfiles.com",
                ".anonfiles.com", "/forms/doLogin", "https://x.example/a?b=1", "login.microsoftonline.com/*"]
        drop = ["GET", "POST", "403", "svcctl", "ITaskSchedulerService", ".{150}", "$(", "password",
                "399629", "dns", "true", "some value with spaces"]
        assert [v for v in keep if not ok(v)] == []
        assert [v for v in drop if ok(v)] == []

    def test_http_method_value_stays_on_observable_not_indicators(self):
        r = extract_elastic_fields('http.request.method : "POST" and url.domain : "evil.example.com"', "kql")
        assert _obs(r, "http.request.method")[0].values == ["POST"]
        assert r.network_indicators == ["evil.example.com"]
