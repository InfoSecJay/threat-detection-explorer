"""Splunk SPL findings from the 2026-08-30 semantic review (issue #59),
plus the cross-cutting classify / field-map batch."""

from __future__ import annotations

from app.services.field_extractor import _classify_field, extract_splunk_fields


def _obs(r, field):
    return [o for o in r.observables if o.field.lower() == field.lower()]


def test_escu_process_macros_name_the_process():
    r = extract_splunk_fields("| tstats count from datamodel=Endpoint.Processes where `process_rundll32` Processes.process=*/i:* by Processes.dest")
    assert "rundll32.exe" in r.process_names
    r = extract_splunk_fields("| tstats count from datamodel=Endpoint.Processes where `process_powershell` by Processes.dest")
    assert set(r.process_names) == {"powershell.exe", "pwsh.exe"}


def test_escu_source_macros_become_source_tables():
    r = extract_splunk_fields("`sysmon` EventCode=7 ImageLoaded=*\\\\wlbsctrl.dll | stats count by dest")
    assert "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" in r.source_tables
    assert r.event_ids == ["7"]
    r = extract_splunk_fields("`wineventlog_security` EventCode=4663 object_file_path=\"*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*\"")
    assert "XmlWinEventLog:Security" in r.source_tables
    assert r.registry_keys == ["*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*"]
    r = extract_splunk_fields("`unknown_macro` field=x")
    assert r.source_tables == []


def test_path_fields_and_command_line_tokens_feed_process_names():
    r = extract_splunk_fields("`sysmon` EventCode=10 TargetImage=*lsass.exe NOT (SourceUser=\"NT AUTHORITY\\\\*\")")
    assert r.process_names == ["lsass.exe"]
    su = _obs(r, "SourceUser")[0]
    assert su.negated is True and (su.type, su.subtype) == ("authentication", "user")
    r = extract_splunk_fields('`wineventlog_security` EventCode=4698 TaskContent IN ("*powershell.exe*", "*pwsh.exe*", "*cmd /c*")')
    assert r.process_names == ["powershell.exe", "pwsh.exe"]
    assert _obs(r, "TaskContent")[0].subtype == "command_line_pattern"


def test_registry_key_fields_reach_registry_keys_without_a_hive():
    r = extract_splunk_fields('| tstats count from datamodel=Endpoint.Registry where Registry.registry_path="*\\\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\\\Shell\\\\open\\\\command*"')
    assert r.registry_keys == ["*\\\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\\\Shell\\\\open\\\\command*"]


def test_null_thresholds_and_placeholders_are_not_values():
    r = extract_splunk_fields("index=web Web.http_user_agent != null | where ut_shannon > 3 csUserAgent!=\"-\"")
    assert r.observables == []
    assert {"Web.http_user_agent", "ut_shannon"} <= set(r.fields_used)


def test_field_map_batch_and_token_heuristics():
    assert _classify_field("dns.question.registered_domain") == ("dns", "query_name")
    assert _classify_field("dll.code_signature.subject_name") == ("file", "code_signature")
    assert _classify_field("graph.relations.relationship") != ("network", "network_field")
    assert _classify_field("source.ip") == ("network", "ip_address") or _classify_field("source.ip")[0] == "network"
    assert _classify_field("cIP") == ("network", "ip_address")
    assert _classify_field("csUserAgent") == ("network", "user_agent")
    assert _classify_field("winlog.event_data.SubjectUserSid") == ("authentication", "user_id")
    assert _classify_field("process.pe.imphash") == ("process", "process_hash")
    assert _classify_field("whitelistEntry") == ("network", "ip_address")
    assert _classify_field("someSubjectField") == ("email", "email_field")
