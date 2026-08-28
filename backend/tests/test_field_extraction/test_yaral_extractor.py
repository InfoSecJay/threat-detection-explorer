"""Tests for the YARA-L (Google SecOps) extractor (issue #6 tail).

Fixtures mirror real Chronicle community rules: SAP audit logon
correlation, a Windows process-launch rule with scalar helpers and a
regex literal, cloud API method matching, and reference-list
membership.
"""

from app.services.yaral_extractor import extract_yaral_fields

SAP = '''
meta:
    author = "Google Cloud Security"
  events:
    $e.metadata.log_type = "SAP_SECURITY_AUDIT"
    (
        $e.metadata.event_type = "USER_LOGIN" or
        $e.additional.fields["msg_1"] = /^AU1$|^AU5$/
    )
    $e.principal.ip_geo_artifact.location.country_or_region != ""
    $user = $e.principal.user.userid
  match:
    $user over 1h
  condition:
    $e
'''

WINDOWS = '''
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.metadata.product_event_type = "4688"
    strings.to_lower($e.target.process.command_line) = "whoami /all"
    re.regex($e.target.process.file.full_path, `\\\\powershell\\.exe$`) nocase
    strings.contains($e.principal.process.file.full_path, "cmd.exe")
    not $e.principal.user.userid = "SYSTEM"
    $e.target.registry.registry_key = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  condition:
    $e
'''

CLOUD = '''
  events:
    $e.metadata.vendor_name = "Google Cloud Platform"
    $e.metadata.product_event_type = "google.iam.admin.v1.CreateServiceAccountKey"
    $e.principal.ip in %corp_egress_ranges
    $e.network.http.user_agent in ("curl", "python-requests")
    net.ip_in_range_cidr($e.target.ip, "10.0.0.0/8")
  condition:
    $e
'''


def test_sap_rule_fields_tables_and_complexity():
    r = extract_yaral_fields(SAP)
    assert "SAP_SECURITY_AUDIT" in r.source_tables
    assert "metadata.event_type" in r.fields_used
    # map access normalizes to a dotted path
    assert "additional.fields.msg_1" in r.fields_used
    # placeholder assignment records the field without a value
    assert "principal.user.userid" in r.fields_used
    assert not any(o.field == "principal.user.userid" for o in r.observables)
    # regex literal captured as the value
    rx = [o for o in r.observables if o.field == "additional.fields.msg_1"]
    assert rx and rx[0].values == ["^AU1$|^AU5$"]
    # `!= ""` is a non-empty check: the FIELD is real, "" is not a value
    assert "principal.ip_geo_artifact.location.country_or_region" in r.fields_used
    assert not any(o.field.endswith("country_or_region") for o in r.observables)
    # match: window makes it complex
    assert r.query_complexity == "complex"


def test_windows_rule_unwraps_helpers_and_routes_surfaces():
    r = extract_yaral_fields(WINDOWS)
    assert "4688" in r.event_ids
    cl = [o for o in r.observables if o.field == "target.process.command_line"]
    assert cl and cl[0].values == ["whoami /all"]
    assert cl[0].type == "process" and cl[0].subtype == "command_line_pattern"
    # re.regex value is the backtick pattern; process path -> process_names
    assert "powershell.exe" in r.process_names
    assert "cmd.exe" in r.process_names
    parent = [o for o in r.observables if o.field == "principal.process.file.full_path"]
    assert parent and parent[0].subtype == "parent_process_path"
    # `not` prefix negates
    sysu = [o for o in r.observables if o.field == "principal.user.userid"]
    assert sysu and sysu[0].negated
    assert any("CurrentVersion" in k for k in r.registry_keys)
    assert r.query_complexity in ("simple", "moderate")


def test_cloud_rule_api_actions_lists_and_cidr():
    r = extract_yaral_fields(CLOUD)
    assert "google.iam.admin.v1.CreateServiceAccountKey" in r.api_actions
    assert not r.event_ids
    # %reference_list: field recorded, no value
    assert "principal.ip" in r.fields_used
    assert not any(o.field == "principal.ip" for o in r.observables)
    ua = [o for o in r.observables if o.field == "network.http.user_agent"]
    assert ua and set(ua[0].values) == {"curl", "python-requests"}
    assert "10.0.0.0/8" in r.network_indicators


def test_no_events_block_and_junk():
    assert extract_yaral_fields("").fields_used == []
    assert extract_yaral_fields(None).fields_used == []
    assert extract_yaral_fields("meta:\n  x = 1\ncondition:\n  $e").fields_used == []
