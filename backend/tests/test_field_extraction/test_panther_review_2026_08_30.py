"""Panther / pypanther / Auth0 findings from the 2026-08-30 review (#59)."""

from __future__ import annotations

from app.services.field_extractor import extract_panther_fields, extract_sigma_fields, extract_splunk_fields


def _obs(r, field):
    return [o for o in r.observables if o.field == field]


def test_reject_guard_records_the_required_value_positively():
    src = (
        "def rule(event):\n"
        '    if event.get("eventName") != "AssumeRole":\n'
        "        return False\n"
        '    if event.deep_get("userIdentity", "type") not in ["IAMUser", "FederatedUser"]:\n'
        "        return False\n"
        "    return True\n"
    )
    r = extract_panther_fields(src)
    o = _obs(r, "eventName")[0]
    assert o.values == ["AssumeRole"] and o.negated is False
    assert r.api_actions == ["AssumeRole"]
    assert _obs(r, "userIdentity.type")[0].negated is False


def test_plain_return_comparison_keeps_its_negation():
    r = extract_panther_fields('def rule(event):\n    return event.get("eventName") != "AssumeRole"\n')
    assert _obs(r, "eventName")[0].negated is True
    assert r.api_actions == []


def test_self_constants_resolve_and_method_chains_unwrap():
    src = (
        "class R(Rule):\n"
        '    EVENTS = {"account_disabled_password_leak", "account_disabled_generic"}\n'
        '    ROLES = ["roles/iam.serviceAccountTokenCreator"]\n'
        "    def rule(self, event):\n"
        '        if event.get("name") in self.EVENTS:\n'
        "            return True\n"
        '        return event.get("GRANTEE_NAME").lower() == "public" or event.deep_get("role") in self.ROLES\n'
    )
    r = extract_panther_fields(src)
    assert set(_obs(r, "name")[0].values) == {"account_disabled_password_leak", "account_disabled_generic"}
    assert set(r.api_actions) >= {"account_disabled_password_leak", "account_disabled_generic"}
    assert _obs(r, "GRANTEE_NAME")[0].values == ["public"]
    assert _obs(r, "role")[0].values == ["roles/iam.serviceAccountTokenCreator"]


def test_placeholders_are_neither_values_nor_path_segments():
    src = (
        "def title(event):\n"
        '    reason = event.get("stopReason", "<UNKNOWN REASON>")\n'
        '    if reason == "<UNKNOWN REASON>":\n'
        "        return 'x'\n"
        "def rule(event):\n"
        '    ua = event.deep_get("properties", "userAgent", "<NO_USERAGENT>")\n'
        '    return ua == "BAV2ROPC"\n'
    )
    r = extract_panther_fields(src)
    assert _obs(r, "stopReason") == []
    assert "properties.userAgent" in r.fields_used
    assert not any("<" in f for f in r.fields_used)
    assert _obs(r, "properties.userAgent")[0].values == ["BAV2ROPC"]


def test_panther_scope_field_map():
    src = (
        "def rule(event):\n"
        '    return event.get("action") == "public_key.create" or event.get("event") == "cert.create"\n'
    )
    r = extract_panther_fields(src)
    assert (_obs(r, "action")[0].type, _obs(r, "action")[0].subtype) == ("cloud", "api_action")
    assert set(r.api_actions) == {"public_key.create", "cert.create"}


def test_auth0_operations_and_placeholders():
    r = extract_splunk_fields('index=auth0 data.type=sapi data.description="Update a client" data.tenant_name="{your-tenant-name}"')
    assert r.api_actions == ["Update a client"]
    assert _obs(r, "data.tenant_name") == []
    assert "data.tenant_name" in r.fields_used
    r = extract_splunk_fields('index=auth0 data.type=gd_send_sms data.description="Guardian - SMS sent"')
    assert r.api_actions == []
    r = extract_sigma_fields({"selection": {"data.type": "mgmt_api_read", "data.description": "Get client by ID"}, "condition": "selection"})
    assert r.api_actions == ["Get client by ID"]


def test_space_separated_in_lists():
    r = extract_splunk_fields("index=auth0 data.type IN (ss sv reset_pwd_leak)")
    assert _obs(r, "data.type")[0].values == ["ss", "sv", "reset_pwd_leak"]
