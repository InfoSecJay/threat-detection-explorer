"""#138 list C: solution metadata providers become products, content-hub
domains become the fallback domain, and an OS-less domain with no OS
stated reads not_applicable."""

from __future__ import annotations

from types import SimpleNamespace

from app.normalizers.base import NormalizedDetection
from app.services.taxonomy import resolve_for_repo
from app.services.taxonomy.domains import finalize_platforms
from app.services.taxonomy.vendors import sentinel as vsentinel


def _stub(**kw):
    ns = SimpleNamespace(log_source=None, extra=None, tags=None, detection_logic_raw=None, file_path="", source="sentinel")
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_providers_become_products_and_domains_cross_walk():
    r = vsentinel.resolve(_stub(extra={
        "kql_tables": ["CynerioEvent_CL"],
        "solution_metadata": {"providers": ["Cynerio"], "domains": ["security - vulnerability management", "security - network"]},
    }))
    assert r["products"] == ["cynerio"]
    assert r["domains"] == ["network"]  # vulnerability management has no telemetry meaning


def test_publisher_and_alias_handling():
    r = vsentinel.resolve(_stub(extra={"kql_tables": ["AWSCloudTrail"], "solution_metadata": {"providers": ["Amazon Web Services"], "domains": ["cloud provider"]}}))
    assert r["products"] == ["aws"] and r["domains"] == ["cloud"]
    r = vsentinel.resolve(_stub(extra={"kql_tables": ["SecurityEvent"], "solution_metadata": {"providers": ["Microsoft"], "domains": ["security - threat protection"]}}))
    assert r["products"] == [] and r["domains"] == []
    r = vsentinel.resolve(_stub(extra={"solution_metadata": {"providers": ["Data443 Risk Mitigation, Inc."], "domains": []}}))
    assert r["products"] == ["data443"]
    r = vsentinel.resolve(_stub(extra={"solution_metadata": {"providers": ["ZeroFox, Inc."], "domains": []}}))
    assert r["products"] == ["zerofox"]


def test_facade_passes_hints_through():
    result = resolve_for_repo("sentinel", _stub(extra={
        "kql_tables": ["IllumioSyslogAuditEvents"],
        "solution_metadata": {"providers": ["Illumio"], "domains": ["security - network"]},
    }))
    assert result["products"] == ["illumio"] and result["domains"] == ["network"]


def _detection(**kw) -> NormalizedDetection:
    base = dict(
        id="x", source="sentinel", source_file="r.yaml", source_repo_url="https://x", title="t", description="d",
        author=None, detection_logic="q", language="kql", raw_content="raw", severity="high", status="stable",
        event_types=["audit_event"],
    )
    base.update(kw)
    return NormalizedDetection(**base)


def test_normalizer_merges_hints_and_finalizes_platform():
    n = _detection(platforms=[], data_sources=["siem_alert"], products=["cynerio"], domains=["network"])
    assert n.products == ["cynerio"]
    assert n.domains == ["network"]
    assert n.platforms == ["not_applicable"]


def test_derived_values_win_over_hints():
    # The table said okta; the metadata domain is only a fallback and the
    # provider product dedupes against a derived one with the same prefix.
    n = _detection(platforms=["okta"], data_sources=["okta_system_log"], products=["okta"], domains=["cloud"])
    assert n.domains == ["identity"] and n.products == ["okta"]
    n = _detection(platforms=["cisco_umbrella"], data_sources=["cisco_umbrella_dns"], products=["cisco"], domains=[])
    assert n.products == ["cisco_umbrella"]


def test_endpoint_or_unknown_domain_keeps_platform_unknown():
    assert finalize_platforms(["unknown"], ["endpoint"]) == ["unknown"]
    assert finalize_platforms(["unknown"], ["unknown"]) == ["unknown"]
    assert finalize_platforms(["unknown"], []) == ["unknown"]
    assert finalize_platforms(["windows"], ["network"]) == ["windows"]
    assert finalize_platforms(["unknown"], ["network", "cloud"]) == ["not_applicable"]
