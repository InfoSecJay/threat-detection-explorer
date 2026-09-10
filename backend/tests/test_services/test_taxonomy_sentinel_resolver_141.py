"""#141: the Sentinel resolver must attribute a multi-vendor table to
the vendor the query names, never to a fixed vendor list, and must not
union every tier. Fixtures mirror real upstream rules."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.taxonomy.domains import split_platforms
from app.services.taxonomy.vendors import sentinel as vsentinel

FIREWALLS = {"cisco_firewall", "fortinet_firewall", "palo_alto_firewall"}


def _stub(**kw):
    ns = SimpleNamespace(log_source=None, extra=None, tags=None, detection_logic_raw=None, file_path="")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _resolve(**extra):
    return vsentinel.resolve(_stub(extra=extra))


class TestCommonSecurityLog:
    def test_acronis_is_acronis(self):
        r = _resolve(
            kql_tables=["CommonSecurityLog"],
            kql_filters={"devicevendor": ["acronis"]},
            solution_folder="Acronis Cyber Protect Cloud",
        )
        assert not (FIREWALLS & r["data_sources"])
        assert "antivirus_logs" in r["data_sources"]
        platforms, domains, products = split_platforms(list(r["platforms"]), list(r["data_sources"]))
        assert products == ["acronis"] and domains == ["endpoint"]

    def test_palo_alto_is_only_palo_alto(self):
        r = _resolve(kql_tables=["CommonSecurityLog"], kql_filters={"devicevendor": ["palo alto networks"]})
        assert r["data_sources"] == {"palo_alto_firewall"}

    def test_vectra_and_arista_are_ndr_vendors(self):
        for vendor, product in (("vectra networks", "vectra"), ("arista networks", "arista")):
            r = _resolve(kql_tables=["CommonSecurityLog"], kql_filters={"devicevendor": [vendor]})
            assert not (FIREWALLS & r["data_sources"])
            assert product in split_platforms(list(r["platforms"]), list(r["data_sources"]))[2]

    def test_generic_cef_with_no_vendor_is_generic(self):
        r = _resolve(kql_tables=["CommonSecurityLog"], requiredDataConnectors=[{"connectorId": "CEF", "dataTypes": ["CommonSecurityLog"]}])
        assert r["data_sources"] == {"network_traffic_logs"}
        assert r["platforms"] == {"network_appliance"}

    def test_folder_names_the_vendor_when_the_query_does_not(self):
        r = _resolve(kql_tables=["CommonSecurityLog"], solution_folder="Acronis Cyber Protect Cloud")
        assert "antivirus_logs" in r["data_sources"] and not (FIREWALLS & r["data_sources"])

    def test_specific_table_plus_refined_generic_keeps_both(self):
        r = _resolve(kql_tables=["SecurityEvent", "CommonSecurityLog"], kql_filters={"devicevendor": ["fortinet"]})
        assert r["data_sources"] == {"windows_security_event_log", "fortinet_firewall"}


class TestOtherGenericTables:
    def test_iot_security_alert(self):
        r = _resolve(kql_tables=["SecurityAlert"], kql_filters={"providername": ["iotsecurity"]})
        assert "siem_alert" not in r["data_sources"]
        _, domains, products = split_platforms(list(r["platforms"]), list(r["data_sources"]))
        assert "microsoft_defender" in products and "network" in domains

    def test_security_alert_without_provider_is_unattributed(self):
        r = _resolve(kql_tables=["SecurityAlert"])
        assert r["data_sources"] == {"siem_alert"}
        assert r["platforms"] == set()  # no more microsoft_365 + azure + windows by default

    def test_mdatp_alert_is_defender_endpoint(self):
        r = _resolve(kql_tables=["SecurityAlert"], kql_filters={"providername": ["mdatp"]})
        assert r["data_sources"] == {"defender_endpoint"} and r["platforms"] == {"windows"}

    def test_azurediagnostics_by_category_and_resource(self):
        r = _resolve(kql_tables=["AzureDiagnostics"], kql_filters={"category": ["kube-audit"]})
        assert r["data_sources"] == {"kubernetes_audit"}
        r = _resolve(kql_tables=["AzureDiagnostics"], kql_filters={"resourcetype": ["azurefirewalls"]})
        assert r["data_sources"] == {"azure_firewall"}
        r = _resolve(kql_tables=["AzureDiagnostics"])
        assert r["data_sources"] == {"azure_audit"}

    def test_sysmon_over_windowsevent_and_event(self):
        r = _resolve(kql_tables=["WindowsEvent"], kql_filters={"provider": ["microsoft-windows-sysmon"]})
        assert r["data_sources"] == {"sysmon"} and r["platforms"] == {"windows"}
        r = _resolve(kql_tables=["Event"], kql_filters={"source": ["microsoft-windows-sysmon"]})
        assert r["data_sources"] == {"sysmon"}

    def test_syslog_daemon_is_linux_but_appliance_folder_is_not(self):
        r = _resolve(kql_tables=["Syslog"], kql_filters={"processname": ["sshd"]})
        assert r["data_sources"] == {"linux_syslog"} and r["platforms"] == {"linux"}
        r = _resolve(kql_tables=["Syslog"], solution_folder="CTERA")
        assert "linux" not in r["platforms"]
        r = _resolve(kql_tables=["Syslog"])
        assert r["data_sources"] == {"linux_syslog"}

    def test_category_filter_is_ignored_on_a_non_generic_table(self):
        # `Category == "UserManagement"` on AuditLogs must not be read as an
        # AzureDiagnostics category.
        r = _resolve(kql_tables=["AuditLogs"], kql_filters={"category": ["kube-audit"]})
        assert r["data_sources"] == {"entra_id_audit"}


class TestConnectorsAndFolders:
    def test_connectors_do_not_pile_onto_a_resolved_table(self):
        r = _resolve(
            kql_tables=["SecurityEvent"],
            requiredDataConnectors=[
                {"connectorId": "CEF", "dataTypes": ["CommonSecurityLog"]},
                {"connectorId": "Fortinet", "dataTypes": ["CommonSecurityLog"]},
                {"connectorId": "PaloAltoNetworks", "dataTypes": ["CommonSecurityLog"]},
            ],
        )
        assert r["data_sources"] == {"windows_security_event_log"}

    def test_connectors_resolve_when_no_table_did(self):
        r = _resolve(kql_tables=["_Im_NetworkSession"], requiredDataConnectors=[{"connectorId": "AWSS3", "dataTypes": ["AWSCloudTrail"]}])
        assert "aws" in r["platforms"] or "aws_cloudtrail" in r["data_sources"]

    def test_generic_connector_is_the_last_fallback(self):
        r = _resolve(kql_tables=[], requiredDataConnectors=[{"connectorId": "CEF", "dataTypes": ["CommonSecurityLog"]}])
        assert r["data_sources"] == {"network_traffic_logs"}
        assert not (FIREWALLS & r["data_sources"])

    def test_folder_only_rule_still_resolves(self):
        r = _resolve(solution_folder="Mimecast")
        assert "email_message_metadata" in r["data_sources"]

    def test_unlisted_custom_table_takes_the_catch_all(self):
        r = _resolve(kql_tables=["NobodyMappedThis_CL"])
        assert r["data_sources"] == {"siem_alert"}
