"""Tests for the Okta System Log (OIE) extractor (issue #6 tail)."""

from app.services.oie_extractor import extract_oie_fields, extract_okta_fields


def test_eq_and_contains_terms_become_identity_observables():
    r = extract_oie_fields(
        'eventType eq "user.risk.detect" and debugContext.debugData.risk co "level=HIGH"'
    )
    assert r.source_tables == ["okta_system_log"]
    ev = [o for o in r.observables if o.field == "eventType"]
    assert ev and ev[0].values == ["user.risk.detect"]
    assert ev[0].type == "identity" and ev[0].subtype == "action"
    # identity/action routes to the api_actions surface
    assert "user.risk.detect" in r.api_actions
    risk = [o for o in r.observables if o.field == "debugContext.debugData.risk"]
    assert risk and risk[0].values == ["level=HIGH"] and risk[0].subtype == "risk"


def test_ne_and_not_negate_and_pr_is_field_only():
    r = extract_oie_fields(
        'outcome.result ne "SUCCESS" and not target.displayName eq "Admin" and client.device pr'
    )
    outcome = [o for o in r.observables if o.field == "outcome.result"][0]
    assert outcome.negated and outcome.subtype == "outcome"
    target = [o for o in r.observables if o.field == "target.displayName"][0]
    assert target.negated
    assert "Admin" in r.target_resources or target.subtype == "target"
    assert "client.device" in r.fields_used
    assert not any(o.field == "client.device" for o in r.observables)


def test_ip_prefix_lands_on_network_surface_and_complexity():
    r = extract_oie_fields(
        'client.ipAddress sw "10." and eventType eq "a" or eventType eq "b" and outcome.result eq "FAILURE"'
    )
    assert "10." in r.network_indicators or any(
        o.field == "client.ipAddress" for o in r.observables
    )
    assert r.query_complexity == "moderate"


def test_dispatch_spl_variant_uses_splunk_extractor():
    r = extract_okta_fields(
        'index=okta eventType="user.session.start" | stats count by actor.alternateId', "spl"
    )
    assert "okta" in r.source_tables
    assert "actor.alternateId" in r.fields_used


def test_empty_and_junk():
    assert extract_oie_fields("").fields_used == []
    assert extract_oie_fields(None).fields_used == []
    assert extract_oie_fields("just prose without operators").fields_used == []
