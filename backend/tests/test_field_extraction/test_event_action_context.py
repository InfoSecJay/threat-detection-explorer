"""ECS `event.action` is context-dependent: an endpoint telemetry verb
("start", "exec", "creation") on host streams, an API / audit operation
("CreateUser", "user.session.start") on cloud and identity streams.
Before this pass every event.action was cloud/api_action -- a Linux
file-access rule rendered a CLOUD group and "exec" led the api_actions
facet (2,214 observables, ~85% endpoint verbs, 2026-08-28 census).
"""

import pytest

from app.services.field_extractor import (
    _index_domain,
    extract_elastic_fields,
    extract_esql_fields,
)


def _event_action(result):
    obs = [o for o in result.observables if o.field == "event.action"]
    assert len(obs) == 1, obs
    return obs[0]


class TestEndpointStaysEndpoint:
    def test_eql_process_head(self):
        r = extract_elastic_fields('process where event.action == "start"', "eql")
        o = _event_action(r)
        assert (o.type, o.subtype) == ("event", "event_action")
        assert r.api_actions == []

    def test_reported_rule_shape_file_access_on_linux(self):
        # detectionexplorer.io/detections/75cccff3-... : GenAI process
        # accessing sensitive files. Rendered a CLOUD group before.
        q = (
            'file where event.action in ("open", "creation", "modification") '
            'and event.outcome == "success" and host.os.type == "linux" '
            'and file.name in (".bashrc", ".zshrc")'
        )
        r = extract_elastic_fields(q, "eql")
        o = _event_action(r)
        assert (o.type, o.subtype) == ("event", "event_action")
        assert o.values == ["open", "creation", "modification"]
        assert r.api_actions == []

    def test_kql_host_os_and_event_category(self):
        q = "host.os.type:linux and event.category:process and event.action:exec"
        r = extract_elastic_fields(q, "kql")
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_kql_winlog_namespace(self):
        q = 'event.action:"logged-in" and winlog.event_data.LogonType:10'
        r = extract_elastic_fields(q, "kql")
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_kql_endpoint_dataset(self):
        q = "event.dataset:endpoint.events.process and event.action:exec"
        r = extract_elastic_fields(q, "kql")
        assert _event_action(r).type == "event"

    def test_rule_indices_endpoint(self):
        q = 'event.action:"start" and event.outcome:success'
        r = extract_elastic_fields(
            q, "kql", indices=["logs-endpoint.events.process-*", "winlogbeat-*"]
        )
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_esql_endpoint_from(self):
        q = 'FROM logs-endpoint.events.process-* | WHERE event.action == "start"'
        r = extract_esql_fields(q)
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_cloud_defend_is_runtime_endpoint_telemetry(self):
        q = "event.action:exec and process.name:kubectl"
        r = extract_elastic_fields(q, "kql", indices=["logs-cloud_defend.process*"])
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_protections_default_domain(self):
        # `any where` head + no other context: the caller default decides.
        q = 'any where event.action == "already_running"'
        r = extract_elastic_fields(q, "eql", default_domain="endpoint")
        assert _event_action(r).type == "event"
        assert r.api_actions == []


class TestCloudBecomesApiAction:
    def test_kql_dataset(self):
        q = "event.dataset:aws.cloudtrail and event.action:CreateUser"
        r = extract_elastic_fields(q, "kql")
        o = _event_action(r)
        assert (o.type, o.subtype) == ("cloud", "api_action")
        assert r.api_actions == ["CreateUser"]

    def test_rule_indices_cloud(self):
        q = 'event.action:"ConsoleLogin" and event.outcome:failure'
        r = extract_elastic_fields(q, "kql", indices=["filebeat-*", "logs-aws.cloudtrail*"])
        assert _event_action(r).subtype == "api_action"
        assert r.api_actions == ["ConsoleLogin"]

    def test_integration_only(self):
        q = 'event.action:"ConsoleLogin"'
        r = extract_elastic_fields(q, "kql", indices=["logs-*"], integrations=["aws"])
        assert r.api_actions == ["ConsoleLogin"]

    def test_cloud_namespace(self):
        q = "event.action:AssumeRole and aws.cloudtrail.user_identity.type:IAMUser"
        r = extract_elastic_fields(q, "kql")
        assert r.api_actions == ["AssumeRole"]

    def test_azure_activity_is_cloud(self):
        q = 'event.action:"MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE"'
        r = extract_elastic_fields(q, "kql", indices=["logs-azure.activitylogs*"])
        assert _event_action(r).type == "cloud"

    def test_esql_from_cloudtrail(self):
        q = 'FROM logs-aws.cloudtrail-* | WHERE event.action == "CreateUser"'
        r = extract_esql_fields(q)
        assert _event_action(r).subtype == "api_action"
        assert r.api_actions == ["CreateUser"]

    def test_eql_negated_cloud_action_stays_off_facet(self):
        q = 'any where event.dataset == "aws.cloudtrail" and event.action != "DescribeInstances"'
        r = extract_elastic_fields(q, "eql")
        o = _event_action(r)
        assert o.type == "cloud" and o.negated
        assert r.api_actions == []

    def test_default_domain_cloud(self):
        q = 'event.action:"PutObject"'
        r = extract_elastic_fields(q, "kql", default_domain="cloud")
        assert r.api_actions == ["PutObject"]


class TestIdentityBecomesAction:
    def test_okta_dataset(self):
        q = "event.dataset:okta.system and event.action:user.session.start"
        r = extract_elastic_fields(q, "kql")
        o = _event_action(r)
        assert (o.type, o.subtype) == ("identity", "action")
        assert r.api_actions == ["user.session.start"]

    def test_okta_namespace(self):
        q = 'event.action:"user.mfa.attempt_bypass" and okta.outcome.result:SUCCESS'
        r = extract_elastic_fields(q, "kql")
        assert _event_action(r).type == "identity"

    def test_entra_signin_index_is_identity_not_cloud(self):
        q = 'event.action:"Sign-in activity" and event.outcome:failure'
        r = extract_elastic_fields(q, "kql", indices=["logs-azure.signinlogs*"])
        assert _event_action(r).type == "identity"

    def test_esql_from_okta(self):
        q = 'FROM logs-okta.system-* | WHERE event.action == "user.session.start"'
        r = extract_esql_fields(q)
        assert _event_action(r).type == "identity"
        assert r.api_actions == ["user.session.start"]


class TestUndecidedAndGeneric:
    def test_no_context_stays_neutral_and_off_facet(self):
        r = extract_elastic_fields('event.action:"foo"', "kql")
        o = _event_action(r)
        assert (o.type, o.subtype) == ("event", "event_action")
        assert r.api_actions == []

    def test_firewall_stream_is_generic(self):
        q = 'event.action:"flow_denied"'
        r = extract_elastic_fields(q, "kql", indices=["logs-panw.panos*"])
        assert _event_action(r).type == "event"
        assert r.api_actions == []

    def test_endpoint_namespace_beats_default(self):
        q = 'event.action:"exec" and process.name:"curl"'
        r = extract_elastic_fields(q, "kql", default_domain="cloud")
        assert r.api_actions == []


@pytest.mark.parametrize(
    "pattern, expected",
    [
        ("logs-endpoint.events.process-*", "endpoint"),
        ("logs-endpoint.events.*", "endpoint"),
        ("endgame-*", "endpoint"),
        ("winlogbeat-*", "endpoint"),
        ("logs-windows.sysmon_operational-*", "endpoint"),
        ("logs-system.security*", "endpoint"),
        ("logs-system.auth*", "endpoint"),
        ("auditbeat-*", "endpoint"),
        ("logs-crowdstrike.fdr*", "endpoint"),
        ("logs-sentinel_one_cloud_funnel.*", "endpoint"),
        ("logs-cloud_defend.process*", "endpoint"),
        ("logs-m365_defender.event*", "endpoint"),
        (".ds-logs-endpoint.events.file-default-2024", "endpoint"),
        ("logs-aws.cloudtrail*", "cloud"),
        ("logs-aws*", "cloud"),
        ("logs-azure.activitylogs*", "cloud"),
        ("logs-azure.signinlogs*", "identity"),
        ("logs-azure.auditlogs*", "identity"),
        ("logs-azure.identity_protection*", "identity"),
        ("logs-gcp*", "cloud"),
        ("logs-google_workspace*", "cloud"),
        ("logs-o365.audit*", "cloud"),
        ("logs-github.audit*", "cloud"),
        ("logs-kubernetes.audit*", "cloud"),
        ("logs-okta*", "identity"),
        ("logs-auth0*", "identity"),
        ("logs-panw.panos*", "event"),
        ("logs-network_traffic.*", "event"),
        ("aws.cloudtrail", "cloud"),  # event.dataset value
        ("okta.system", "identity"),  # event.dataset value
        ("zoom.webhook", "cloud"),  # event.dataset value, filebeat-* index
        ("logs-*", None),
        ("filebeat-*", None),
        ("*", None),
        (".alerts-security.alerts-*", None),
        ("", None),
    ],
)
def test_index_domain(pattern, expected):
    assert _index_domain(pattern) == expected
