"""Semantic-review fixes for the OIE extractor (2026-08-30 review).

Cases lifted from the production Okta customer-detections corpus that
the 2026-08-30 review flagged:

1. Escaped quotes inside a value split one term into junk observables
   whose value was a lone backslash.
2. `eventType co "..."` (a contains PATTERN) was promoted onto the
   api_actions surface as if it were an exact event type.
3. Words inside string literals (placeholders like ".../here") must
   never surface in fields_used -- that list is field paths only.
4. `in (...)` / `in [...]` lists yield one value per list item.
5. `not ( ... )` group negation applies to every term in the group.
"""

from app.services.oie_extractor import extract_oie_fields, extract_okta_fields

LOG_ONLY = "debugContext.debugData.logOnlySecurityData"

# Verbatim from request_to_access_admin_console_from_new_device_or_ip.yml
NEW_DEVICE_OR_IP = (
    'eventType eq "policy.evaluate_sign_on" and target.displayName eq "Okta Admin Console" '
    'and ((debugContext.debugData.behaviors co "New Device=POSITIVE" and '
    'debugContext.debugData.behaviors co "New IP=POSITIVE") OR '
    '(debugContext.debugData.logOnlySecurityData co "\\"New Device\\":\\"POSITIVE\\"" or '
    'debugContext.debugData.logOnlySecurityData co "\\"New IP\\":\\"POSITIVE\\""))'
)

# Verbatim from fastpass_auth_via_suspicious_binary.yml (trimmed list)
FASTPASS_BINARY = (
    'debugContext.debugData.factor eq "SIGNED_NONCE" and outcome.result eq "SUCCESS" and '
    'authenticationContext.authenticatorContext.bindingMethod eq "LOOPBACK" and '
    '(authenticationContext.authenticatorContext.validationStatus eq "NO_SIGNATURE" or '
    'not (authenticationContext.authenticatorContext.binaryIdentifier co "Edge" or '
    'authenticationContext.authenticatorContext.binaryIdentifier co "Chrome"))'
)

# Verbatim from api_token_excessive_network_access.yml
API_TOKEN_NETWORK = (
    'eventType in ["system.api_token.create", "system.api_token.update"] AND '
    'debugContext.debugData.networkConnection eq "ANYWHERE"'
)


def _obs(result, field_name):
    return [o for o in result.observables if o.field == field_name]


# ---------------------------------------------------------------------------
# 1. Escaped quotes
# ---------------------------------------------------------------------------

def test_escaped_quotes_yield_one_observable_with_unescaped_value():
    r = extract_oie_fields(LOG_ONLY + ' co "\\"New Device\\":\\"POSITIVE\\""')
    obs = _obs(r, LOG_ONLY)
    assert len(obs) == 1
    assert obs[0].values == ['"New Device":"POSITIVE"']
    assert r.fields_used == [LOG_ONLY]
    assert not any("\\" in v for o in r.observables for v in o.values)


def test_escaped_backslash_is_unescaped():
    r = extract_oie_fields('debugContext.debugData.url co "a\\\\b"')
    assert _obs(r, "debugContext.debugData.url")[0].values == ["a\\b"]


def test_real_rule_new_device_or_ip_keeps_every_term_intact():
    r = extract_oie_fields(NEW_DEVICE_OR_IP)
    assert r.api_actions == ["policy.evaluate_sign_on"]
    assert set(r.fields_used) == {
        "eventType",
        "target.displayName",
        "debugContext.debugData.behaviors",
        LOG_ONLY,
    }
    log_only = _obs(r, LOG_ONLY)
    assert sorted(v for o in log_only for v in o.values) == [
        '"New Device":"POSITIVE"',
        '"New IP":"POSITIVE"',
    ]
    behaviors = _obs(r, "debugContext.debugData.behaviors")
    assert sorted(v for o in behaviors for v in o.values) == [
        "New Device=POSITIVE",
        "New IP=POSITIVE",
    ]
    assert not any(v == "\\" for o in r.observables for v in o.values)
    assert not any(o.negated for o in r.observables)


# ---------------------------------------------------------------------------
# 2. Pattern operators on the action field stay off api_actions
# ---------------------------------------------------------------------------

def test_eq_event_type_still_reaches_api_actions():
    r = extract_oie_fields('eventType eq "user.session.start"')
    assert r.api_actions == ["user.session.start"]
    ev = _obs(r, "eventType")
    assert ev and ev[0].type == "identity" and ev[0].subtype == "action"
    assert not ev[0].negated


def test_contains_event_type_is_a_pattern_not_an_action():
    r = extract_oie_fields('eventType co "user.authentication"')
    ev = _obs(r, "eventType")
    # the typed observable is kept ...
    assert ev and ev[0].values == ["user.authentication"]
    assert ev[0].type == "identity"
    # ... but a contains match is not an action anyone can look up
    assert "user.authentication" not in r.api_actions
    assert r.api_actions == []


def test_sw_and_ew_event_type_are_patterns_too():
    r = extract_oie_fields('eventType sw "user.session" or eventType ew ".start"')
    assert r.api_actions == []
    assert sorted(v for o in _obs(r, "eventType") for v in o.values) == [
        ".start",
        "user.session",
    ]


def test_exact_and_pattern_on_same_field_only_exact_routes():
    r = extract_oie_fields(
        'eventType eq "user.session.start" and eventType co "user.authentication"'
    )
    assert r.api_actions == ["user.session.start"]
    assert sorted(v for o in _obs(r, "eventType") for v in o.values) == [
        "user.authentication",
        "user.session.start",
    ]


# ---------------------------------------------------------------------------
# 3. fields_used is field paths only
# ---------------------------------------------------------------------------

def test_placeholder_url_value_does_not_leak_into_fields_used():
    r = extract_oie_fields(
        'debugContext.debugData.url co "https://example.okta.com/here"'
    )
    assert r.fields_used == ["debugContext.debugData.url"]
    url = _obs(r, "debugContext.debugData.url")
    assert url and url[0].values == ["https://example.okta.com/here"]


def test_operator_lookalikes_inside_string_literals_are_not_terms():
    r = extract_oie_fields(
        'debugContext.debugData.url co "insert your url here eq now" '
        'and outcome.result eq "SUCCESS" '
        'and target.displayName co "fake.field eq \\"x\\" and other.field co"'
    )
    assert r.fields_used == [
        "debugContext.debugData.url",
        "outcome.result",
        "target.displayName",
    ]
    assert "here" not in r.fields_used
    assert "fake.field" not in r.fields_used
    assert "other.field" not in r.fields_used
    assert _obs(r, "target.displayName")[0].values == [
        'fake.field eq "x" and other.field co'
    ]


def test_keywords_never_become_fields():
    r = extract_oie_fields(
        'eventType eq "a" AND NOT outcome.result eq "b" OR client.device pr'
    )
    assert r.fields_used == ["eventType", "outcome.result", "client.device"]
    for kw in ("and", "or", "not", "in", "AND", "NOT", "OR"):
        assert kw not in r.fields_used


# ---------------------------------------------------------------------------
# 4. in (...) / in [...] lists
# ---------------------------------------------------------------------------

def test_in_list_with_parens_each_value_is_separate():
    r = extract_oie_fields(
        'eventType in ("user.session.start","user.session.end") '
        'and outcome.result eq "SUCCESS"'
    )
    assert r.fields_used == ["eventType", "outcome.result"]
    ev = _obs(r, "eventType")
    assert len(ev) == 1
    assert ev[0].values == ["user.session.start", "user.session.end"]
    assert r.api_actions == ["user.session.start", "user.session.end"]


def test_in_list_with_brackets_real_rule():
    r = extract_oie_fields(API_TOKEN_NETWORK)
    assert r.api_actions == ["system.api_token.create", "system.api_token.update"]
    assert r.fields_used == ["eventType", "debugContext.debugData.networkConnection"]
    nc = _obs(r, "debugContext.debugData.networkConnection")
    assert nc and nc[0].values == ["ANYWHERE"]
    assert r.query_complexity == "simple"


def test_in_list_with_escaped_quote_items():
    r = extract_oie_fields(LOG_ONLY + ' in ("\\"a\\":1", "b")')
    assert _obs(r, LOG_ONLY)[0].values == ['"a":1', "b"]


def test_negated_in_list_does_not_route():
    r = extract_oie_fields('not eventType in ("user.session.start", "user.session.end")')
    ev = _obs(r, "eventType")
    assert ev and ev[0].negated
    assert r.api_actions == []


# ---------------------------------------------------------------------------
# 5. not ( ... ) groups
# ---------------------------------------------------------------------------

def test_not_group_negates_every_inner_term():
    r = extract_oie_fields(
        'eventType eq "user.session.start" and not ('
        'target.detailEntry.MethodTypeUsed eq "otp" or '
        'target.detailEntry.MethodTypeUsed eq "push")'
    )
    method = _obs(r, "target.detailEntry.MethodTypeUsed")
    assert len(method) == 2 and all(o.negated for o in method)
    assert not _obs(r, "eventType")[0].negated
    assert r.api_actions == ["user.session.start"]


def test_not_group_keeps_action_off_api_actions():
    r = extract_oie_fields('not (eventType eq "user.session.start")')
    ev = _obs(r, "eventType")
    assert ev and ev[0].negated and ev[0].values == ["user.session.start"]
    assert r.api_actions == []


def test_negation_scope_ends_at_group_close():
    r = extract_oie_fields(
        'a.b eq "1" and (c.d eq "2" or not (e.f co "3" or e.f co "4")) and g.h eq "5"'
    )
    assert all(o.negated for o in _obs(r, "e.f"))
    assert not _obs(r, "a.b")[0].negated
    assert not _obs(r, "c.d")[0].negated
    assert not _obs(r, "g.h")[0].negated


def test_real_rule_fastpass_binary_negates_only_the_not_group():
    r = extract_oie_fields(FASTPASS_BINARY)
    binary = _obs(r, "authenticationContext.authenticatorContext.binaryIdentifier")
    assert len(binary) == 2 and all(o.negated for o in binary)
    assert sorted(v for o in binary for v in o.values) == ["Chrome", "Edge"]
    for f in (
        "debugContext.debugData.factor",
        "outcome.result",
        "authenticationContext.authenticatorContext.bindingMethod",
        "authenticationContext.authenticatorContext.validationStatus",
    ):
        assert not _obs(r, f)[0].negated, f


def test_double_negation_cancels():
    r = extract_oie_fields('not (outcome.result ne "SUCCESS")')
    assert not _obs(r, "outcome.result")[0].negated
    r = extract_oie_fields('not (not (eventType eq "user.session.start"))')
    assert not _obs(r, "eventType")[0].negated
    assert r.api_actions == ["user.session.start"]


def test_pr_inside_not_group_is_field_only():
    r = extract_oie_fields('not (client.device pr)')
    assert r.fields_used == ["client.device"]
    assert r.observables == []


# ---------------------------------------------------------------------------
# dispatch sanity
# ---------------------------------------------------------------------------

def test_dispatch_oie_language_uses_oie_extractor():
    r = extract_okta_fields('eventType eq "user.session.start"', "oie")
    assert r.source_tables == ["okta_system_log"]
    assert r.api_actions == ["user.session.start"]
