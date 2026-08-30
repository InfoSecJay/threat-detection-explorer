"""The api_actions surface holds audit operations only.

Ambiguous fields (eventType / event_type / ActionType / Activity) carry
an audit action on Okta and Snowflake but a record class on Cisco /
CommonSecurityLog and an endpoint verb on MDE. Values are promoted by
shape: namespaced ("user.session.start", "iam:PassRole",
"Microsoft.Compute/virtualMachines/write", "New-InboxRule") yes;
single tokens ("proxylogs", "IntrusionEvent", "RegistryValueSet",
"Login") no. Wildcard patterns never count as a value.
"""

from __future__ import annotations

from app.services.field_extractor import extract_sentinel_fields, extract_sigma_fields, extract_splunk_fields


def _sigma(selection: dict):
    return extract_sigma_fields({"selection": selection, "condition": "selection"})


def test_okta_event_type_is_an_api_action():
    r = _sigma({"eventType": ["user.session.start", "user.account.lock"]})
    assert r.api_actions == ["user.session.start", "user.account.lock"]
    assert [(o.type, o.subtype) for o in r.observables if o.field == "eventType"] == [("identity", "action")]


def test_record_class_event_types_stay_off_the_surface():
    r = extract_sentinel_fields('CommonSecurityLog | where EventType == "proxylogs" or EventType == "message"')
    assert r.api_actions == []
    r = extract_splunk_fields('index=cisco EventType=IntrusionEvent OR EventType=ConnectionEvent')
    assert r.api_actions == []
    r = extract_sentinel_fields('DeviceEvents | where ActionType == "RegistryValueSet"')
    assert r.api_actions == []
    r = extract_splunk_fields('index=snowflake EVENT_TYPE=Login')
    assert r.api_actions == []


def test_hyphenated_and_slashed_operations_count():
    r = _sigma({"eventType": "New-InboxRule"})
    assert r.api_actions == ["New-InboxRule"]
    r = _sigma({"activity": "Microsoft.Compute/virtualMachines/write"})
    assert r.api_actions == ["Microsoft.Compute/virtualMachines/write"]


def test_unambiguous_fields_are_unaffected():
    r = _sigma({"eventName": ["ConsoleLogin", "CreateUser"], "operationName": "Consent to application"})
    assert set(r.api_actions) == {"ConsoleLogin", "CreateUser", "Consent to application"}


def test_wildcard_patterns_are_dropped():
    r = _sigma({"eventName": ["Assume*", "CreateAccessKey"], "eventType": "user.authentication.*"})
    assert r.api_actions == ["CreateAccessKey"]


def test_negated_values_are_not_promoted():
    r = extract_sentinel_fields('OktaSSO | where eventType != "user.session.start"')
    assert r.api_actions == []
