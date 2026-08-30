"""Sentinel KQL findings from the 2026-08-30 semantic review (issue #59)."""

from __future__ import annotations

from app.services.field_extractor import extract_sentinel_fields


def _obs(r, field):
    return [o for o in r.observables if o.field == field]


def test_column_ifexists_and_derived_alias_keep_the_real_column():
    q = (
        'Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID == 18\n'
        '| extend Image = column_ifexists("Image", ""), PipeName = column_ifexists("PipeName", "")\n'
        "| extend process = split(Image, '\\\\', -1)[-1]\n"
        '| where PipeName == "\\\\MICROSOFT##WID\\\\tsql\\\\query"\n'
        '| where process !in ("Microsoft.IdentityServer.ServiceHost.exe", "sqlservr.exe")\n'
        '| where process =~ "wsmprovhost.exe"'
    )
    r = extract_sentinel_fields(q)
    assert _obs(r, "PipeName")[0].values == ["\\\\MICROSOFT##WID\\\\tsql\\\\query"]
    image = _obs(r, "Image")
    assert [o.values for o in image if o.negated] == [["Microsoft.IdentityServer.ServiceHost.exe", "sqlservr.exe"]]
    assert [o.values for o in image if not o.negated] == [["wsmprovhost.exe"]]
    assert r.process_names == ["wsmprovhost.exe"]
    assert r.event_ids == ["18"]
    assert _obs(r, "Source")[0].type == "event"


def test_let_lists_and_suffixed_columns_resolve():
    q = (
        'let AdminActivity = dynamic(["iam.role.create", "user.session.start"]);\n'
        "OktaSSO\n| where eventType_s in (AdminActivity)\n| where outcome_result_s =~ 'SUCCESS'"
    )
    r = extract_sentinel_fields(q)
    assert _obs(r, "eventType_s")[0].values == ["iam.role.create", "user.session.start"]
    assert set(r.api_actions) == {"iam.role.create", "user.session.start"}
    assert (_obs(r, "outcome_result_s")[0].type, _obs(r, "outcome_result_s")[0].subtype) == ("identity", "outcome")


def test_query_parameters_defaults_and_string_lets_substitute():
    q = (
        'declare query_parameters(technicalName:string = "ENTITLEMENT_ADD_FAILED", kind:string = \'ACCESS_ITEM\');\n'
        'let status = "FAILED";\n'
        "SailPointIDN_Events\n| where TechnicalName == technicalName and EventType == kind and Status == status"
    )
    r = extract_sentinel_fields(q)
    assert _obs(r, "TechnicalName")[0].values == ["ENTITLEMENT_ADD_FAILED"]
    assert _obs(r, "Status")[0].values == ["FAILED"]
    assert _obs(r, "EventType")[0].values == ["ACCESS_ITEM"]


def test_verbatim_regex_alternation_and_pattern_guard():
    q = (
        "ADOAuditLogs\n| where OperationName matches regex \"Artifacts.Feed.(Org|Project).Modify\"\n"
        "| where UrlOriginal matches regex @'(10\\.\\d{1,3}\\.\\d{1,3})'"
    )
    r = extract_sentinel_fields(q)
    assert set(r.api_actions) == {"Artifacts.Feed.Org.Modify", "Artifacts.Feed.Project.Modify"}
    assert _obs(r, "UrlOriginal")[0].values == ["(10\\.\\d{1,3}\\.\\d{1,3})"]
    assert r.network_indicators == []


def test_numeric_ids_and_negated_ips_stay_off_surfaces():
    q = (
        'VeeamBackup_CL\n| where instanceId == 24050\n'
        "W3CIISLog\n| where cIP != \"::1\" and csUserAgent !in~ (\"-\", \"MSRPC\") and csUserAgent has \"python-requests\""
    )
    r = extract_sentinel_fields(q)
    assert r.target_resources == []
    assert r.network_indicators == []
    ua = [o for o in _obs(r, "csUserAgent") if not o.negated][0]
    assert (ua.type, ua.subtype) == ("network", "user_agent") and ua.values == ["python-requests"]


def test_extend_hygiene_and_duplicate_collapse():
    q = (
        'let base = SecurityEvent | where EventID == 4688;\n'
        "base\n| extend D = format_datetime(TimeGenerated, 'dd.MM.yyyy HH:mm'), Sev = case(Level == 1, \"Critical\", \"Low\")\n"
        "| where EventID == 4688"
    )
    r = extract_sentinel_fields(q)
    for junk in ("format_datetime", "dd.MM.yyyy", "HH", "Critical", "Low", "case"):
        assert junk not in r.fields_used
    assert "TimeGenerated" in r.fields_used and "Level" in r.fields_used
    assert len(_obs(r, "EventID")) == 1
