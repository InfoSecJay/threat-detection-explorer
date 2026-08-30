"""Unknown-data-source cleanup (#62 #63 #64 + prod audit 2026-08-30):
tables hidden in KQL let-bindings, comma-separated SecOps data_source
lists, new mapping entries, and drift telemetry for rules that resolve
without a data source."""

from __future__ import annotations

from types import SimpleNamespace

from app.parsers.sentinel import _extract_kql_tables
from app.services.ingestion_errors import IngestionStats
from app.services.taxonomy.vendors import (
    google_secops as vsecops,
    sentinel as vsentinel,
    sigma as vsigma,
    splunk as vsplunk,
)
from app.services.taxonomy_notifier import _format_drift_body


def _stub(**kw):
    ns = SimpleNamespace(log_source=None, extra=None, tags=None, detection_logic_raw=None, file_path="")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestKqlLetTables:
    def test_table_inside_let_binding_is_recovered(self):
        q = 'let inds = ThreatIntelIndicators | where Active == true;\ninds | join SigninLogs on IP'
        tables = _extract_kql_tables(q)
        assert "ThreatIntelIndicators" in tables

    def test_function_call_rhs_is_not_a_table(self):
        q = 'let bad = dynamic(["a", "b"]);\nlet t = datatable(x: string)["y"];\nSecurityEvent | take 1'
        assert _extract_kql_tables(q) == ["SecurityEvent"]


class TestSentinelMappings:
    def test_gcp_dns_table(self):
        r = vsentinel.resolve(_stub(extra={"kql_tables": ["GCPCloudDNS"]}))
        assert "gcp_dns" in r["data_sources"] and "gcp" in r["platforms"]

    def test_mimecast_solution_folder(self):
        r = vsentinel.resolve(_stub(extra={"solution_folder": "Mimecast"}))
        assert "email_message_metadata" in r["data_sources"]

    def test_w3ciislog_is_webserver_logs(self):
        r = vsentinel.resolve(_stub(extra={"kql_tables": ["W3CIISLog"]}))
        assert "webserver_logs" in r["data_sources"]

    def test_appservices_av_scan_rule_resolves(self):
        # The #64 sample: Detections/AzureAppServices, no connectors.
        r = vsentinel.resolve(_stub(extra={"kql_tables": ["AppServiceAntivirusScanAuditLogs"], "requiredDataConnectors": []}))
        assert "azure_app_service" in r["data_sources"]


class TestSplunkMappings:
    def test_secureapp_macro(self):
        r = vsplunk.resolve(_stub(extra={}, detection_logic_raw={"search": "`secureapp_attack` | stats count"}))
        assert "application_logs" in r["data_sources"]

    def test_splunk_platform_label(self):
        r = vsplunk.resolve(_stub(extra={"data_source": ["Splunk"]}, detection_logic_raw={"search": "index=_internal"}))
        assert "splunk_internal_logs" in r["data_sources"]

    def test_crowdstrike_identities_macro(self):
        r = vsplunk.resolve(_stub(extra={}, detection_logic_raw={"search": "`crowdstrike_identities` | search x"}))
        assert "crowdstrike_identity_protection" in r["data_sources"]


class TestSecOpsCommaLists:
    def test_multi_product_data_source_unions_every_match(self):
        r = vsecops.resolve(_stub(extra={"data_source": "microsoft sysmon, crowdstrike, zscalar"}))
        assert {"sysmon", "crowdstrike_fdr", "proxy_logs"} <= set(r["data_sources"])

    def test_single_value_still_works(self):
        r = vsecops.resolve(_stub(extra={"data_source": "aws cloudtrail"}))
        assert "aws_cloudtrail" in r["data_sources"]


class TestSigmaWindowsChannels:
    def test_wmi_service_channel(self):
        r = vsigma.resolve(_stub(log_source={"product": "windows", "service": "wmi"}))
        assert "windows_event_logs" in r["data_sources"]

    def test_linux_auth(self):
        r = vsigma.resolve(_stub(log_source={"product": "linux", "service": "auth"}))
        assert "linux_syslog" in r["data_sources"]

    def test_category_only_stays_sourceless_by_design(self):
        r = vsigma.resolve(_stub(log_source={"product": "linux", "category": "process_creation"}))
        assert not r["data_sources"] or set(r["data_sources"]) == {"unknown"}


class TestDriftTelemetry:
    def test_matched_without_data_source_is_tracked(self):
        stats = IngestionStats()
        stats.record_taxonomy_result(
            matched=True, fingerprint="sigma:linux/-/process_creation",
            rule_id="r1", source_file="a.yml", title="T", has_data_source=False,
        )
        stats.record_taxonomy_result(
            matched=True, fingerprint="sigma:linux/-/process_creation",
            rule_id="r2", source_file="b.yml", title="T2", has_data_source=False,
        )
        stats.record_taxonomy_result(
            matched=True, fingerprint="sigma:aws/cloudtrail/-",
            rule_id="r3", source_file="c.yml", title="T3", has_data_source=True,
        )
        assert stats.taxonomy_matched_count == 3
        assert stats.taxonomy_no_datasource_count == 2
        bucket = stats.taxonomy_no_datasource_by_fingerprint["sigma:linux/-/process_creation"]
        assert bucket["count"] == 2 and bucket["samples"][0]["rule_id"] == "r1"
        d = stats.to_dict()
        assert d["taxonomy_no_datasource"] == 2
        assert "sigma:linux/-/process_creation" in d["taxonomy_no_datasource_by_fingerprint"]
        assert stats.to_summary_dict()["taxonomy_no_datasource"] == 2

    def test_drift_body_renders_no_datasource_section(self):
        body = _format_drift_body("sigma", {
            "taxonomy_unmatched": 0,
            "taxonomy_matched": 10,
            "taxonomy_coverage_percent": 100.0,
            "taxonomy_no_datasource": 2,
            "taxonomy_no_datasource_by_fingerprint": {
                "sigma:linux/-/process_creation": {
                    "count": 2,
                    "samples": [{"rule_id": "x", "source_file": "a.yml", "title": "Linux Thing"}],
                },
            },
        }, "job-1")
        assert "## Mapped, but no data source" in body
        assert "sigma:linux/-/process_creation" in body and "Linux Thing" in body
        assert "**2**" in body
