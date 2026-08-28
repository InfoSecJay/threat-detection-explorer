"""Tests for the Panther Python AST field extractor (issue #6).

Pinned on real panther-analysis idioms: `event.get()`, chained
`.get("a", {}).get("b")`, `deep_get(event, ...)`, subscripts,
module-level constant collections, and the non-Python fallback for
correlation/declarative rules.
"""

from app.services.field_extractor import extract_panther_fields


def test_event_get_equality_term():
    src = (
        "def rule(event):\n"
        "    return event.get(\"type\") == \"admin_api_key_created\"\n"
    )
    r = extract_panther_fields(src)
    assert "type" in r.fields_used
    obs = [o for o in r.observables if o.field == "type"]
    assert obs and obs[0].values == ["admin_api_key_created"]
    assert not obs[0].negated


def test_deep_get_and_chained_get_paths():
    src = (
        "from panther_base_helpers import deep_get\n"
        "def rule(event):\n"
        "    a = deep_get(event, \"userIdentity\", \"type\")\n"
        "    b = event.get(\"requestParameters\", {}).get(\"userName\")\n"
        "    return a == \"Root\" and b is not None\n"
    )
    r = extract_panther_fields(src)
    assert "userIdentity.type" in r.fields_used
    assert "requestParameters.userName" in r.fields_used
    obs = [o for o in r.observables if o.field == "userIdentity.type"]
    assert obs and obs[0].values == ["Root"]


def test_in_against_module_constant():
    src = (
        "SENSITIVE_EVENTS = {\"CreateUser\", \"DeleteUser\"}\n"
        "def rule(event):\n"
        "    return event.get(\"eventName\") in SENSITIVE_EVENTS\n"
    )
    r = extract_panther_fields(src)
    obs = [o for o in r.observables if o.field == "eventName"]
    assert obs and set(obs[0].values) == {"CreateUser", "DeleteUser"}
    # eventName classifies as a cloud api action -> api_actions surface
    assert set(r.api_actions) == {"CreateUser", "DeleteUser"}


def test_not_in_is_negated_and_subscript_access():
    src = (
        "def rule(event):\n"
        "    return event[\"eventSource\"] not in (\"s3.amazonaws.com\",)\n"
    )
    r = extract_panther_fields(src)
    obs = [o for o in r.observables if o.field == "eventSource"]
    assert obs and obs[0].negated


def test_reversed_membership_and_startswith():
    src = (
        "def rule(event):\n"
        "    if \"--decode\" in event.get(\"commandLine\"):\n"
        "        return True\n"
        "    return event.get(\"userAgent\", \"\").startswith((\"aws-cli\", \"Boto3\"))\n"
    )
    r = extract_panther_fields(src)
    cl = [o for o in r.observables if o.field == "commandLine"]
    assert cl and cl[0].values == ["--decode"]
    ua = [o for o in r.observables if o.field == "userAgent"]
    assert ua and set(ua[0].values) == {"aws-cli", "Boto3"}


def test_fields_recorded_outside_comparisons():
    src = (
        "def title(event):\n"
        "    return f\"by {event.get('actor_email')}\"\n"
    )
    r = extract_panther_fields(src)
    assert "actor_email" in r.fields_used


def test_log_types_become_source_tables():
    r = extract_panther_fields("def rule(event):\n    return False\n",
                               log_types=["AWS.CloudTrail", "Okta.SystemLog"])
    assert r.source_tables == ["AWS.CloudTrail", "Okta.SystemLog"]


def test_non_python_body_degrades_to_log_types_only():
    yaml_block = "Detection:\n  - Key: repo\n    Condition: Equals\n"
    r = extract_panther_fields(yaml_block, log_types=["GitHub.Audit"])
    assert r.source_tables == ["GitHub.Audit"]
    assert r.fields_used == []


def test_empty_and_none():
    assert extract_panther_fields("").fields_used == []
    assert extract_panther_fields(None).fields_used == []
