"""#138 list A: Sentinel tables that fell to the `siem_alert` catch-all
although a canonical data source already existed (OktaSSO, BoxEvents,
Cisco_Umbrella, ...). Each table must resolve to its source, and the
platform split must then give the rule a domain and, where the
vocabulary has one, a product. A table renamed upstream fails here
instead of silently sliding back into `siem_alert`."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.taxonomy.domains import split_platforms
from app.services.taxonomy.vendors import sentinel as vsentinel


def _stub(**kw):
    ns = SimpleNamespace(log_source=None, extra=None, tags=None, detection_logic_raw=None, file_path="")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


# table -> (data source, domain, product or None)
CASES = {
    "OktaSSO": ("okta_system_log", "identity", "okta"),
    "BoxEvents": ("box_event", "saas", "box"),
    "SlackAudit": ("slack_audit", "saas", "slack"),
    "Cisco_Umbrella": ("cisco_umbrella_dns", "network", "cisco_umbrella"),
    "Cloudflare": ("cloudflare_http", "network", "cloudflare"),
    "ZPAEvent": ("network_traffic_logs", "network", "zscaler"),
    "ProofpointPOD": ("proofpoint_event", "email", "proofpoint"),
    "MimecastSIEM_CL": ("email_message_metadata", "email", None),
    "ApacheHTTPServer": ("webserver_logs", "network", None),
    "NGINXHTTPServer": ("webserver_logs", "network", None),
    "TomcatEvent": ("webserver_logs", "network", None),
    "OracleWebLogicServerEvent": ("webserver_logs", "network", None),
    "Tailscale_Audit_CL": ("tailscale_audit", "network", "tailscale"),
    "Tailscale_Devices_CL": ("tailscale_audit", "network", "tailscale"),
    "Tailscale_Network_CL": ("tailscale_audit", "network", "tailscale"),
    "NetskopeWebTransactions_CL": ("netskope_audit", "network", "netskope"),
    "Unifi_SiteManager_Sites_CL": ("network_traffic_logs", "network", None),
    "Unifi_SiteManager_Devices_CL": ("network_traffic_logs", "network", None),
    "Unifi_SiteManager_ISPMetrics_CL": ("network_traffic_logs", "network", None),
    "UbiquitiAuditEvent": ("network_traffic_logs", "network", None),
    # list B: vendor feeds take the domain of what the vendor watches
    "Pathlock_TDnR_CL": ("application_logs", "application", "pathlock"),
    "SAPBTPAuditLog_CL": ("application_logs", "application", "sap"),
    "SAPETDAlerts_CL": ("application_logs", "application", "sap"),
    "ContrastADRAttackEvents_CL": ("third_party_security_alerts", "application", "contrast_security"),
    "Authomize_v2_CL": ("third_party_security_alerts", "identity", "authomize"),
    "UniqkeyEvents_CL": ("third_party_security_alerts", "identity", "uniqkey"),
    "BHEAttackPathsData_CL": ("third_party_security_alerts", "identity", "bloodhound"),
    "TheomAlerts_CL": ("third_party_security_alerts", "data", "theom"),
    "CognniIncidents_CL": ("third_party_security_alerts", "data", "cognni"),
    "SenservaPro_CL": ("third_party_security_alerts", "cloud", "senserva"),
    "Sonrai_Tickets_CL": ("third_party_security_alerts", "cloud", "sonrai"),
    "FortyTwoCrunchAPIProtection": ("third_party_security_alerts", "network", "42crunch"),
    "CynerioEvent_CL": ("third_party_security_alerts", "network", "cynerio"),
    "Veeam_GetSecurityEvents": ("application_logs", "application", "veeam"),
}


@pytest.mark.parametrize("table,expected", sorted(CASES.items()))
def test_table_resolves_to_its_canonical_source(table, expected):
    source, domain, product = expected
    r = vsentinel.resolve(_stub(extra={"kql_tables": [table]}))
    data_sources = set(r["data_sources"])
    assert source in data_sources, (table, data_sources)
    assert "siem_alert" not in data_sources, (table, data_sources)

    platforms, domains, products = split_platforms(list(r["platforms"]), list(data_sources))
    assert domain in domains, (table, domains)
    assert "unknown" not in domains, (table, domains)
    assert "unknown" not in platforms, (table, platforms)
    if product:
        assert product in products, (table, products)


def test_unlisted_custom_table_still_takes_the_catch_all():
    # The `*_cl` fallback is the safety net for the long tail; list A
    # narrows what reaches it, it does not remove it.
    r = vsentinel.resolve(_stub(extra={"kql_tables": ["SomeVendorNobodyMapped_CL"]}))
    assert "siem_alert" in set(r["data_sources"])


def test_cyfirma_is_a_product_with_no_domain():
    # External threat-landscape feeds make no attack-surface claim, so
    # the product is recorded and the domain stays unknown on purpose.
    r = vsentinel.resolve(_stub(extra={"kql_tables": ["CyfirmaIndicators_CL"]}))
    platforms, domains, products = split_platforms(list(r["platforms"]), list(r["data_sources"]))
    assert "siem_alert" not in set(r["data_sources"])
    assert products == ["cyfirma"]
    assert domains == ["unknown"]

