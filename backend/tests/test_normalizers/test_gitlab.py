"""GitLab TLDR normalizer: per-document rows from one Markdown file."""

from __future__ import annotations

import pytest

from app.normalizers.gitlab import GitLabNormalizer
from app.parsers.base import ParsedRule
from app.parsers.gitlab import GitLabParser
from app.services.quality_score import score_detection
from app.services.taxonomy import resolve_for_repo
from app.services.upstream_refs import latest_upstream_url, pinned_commit

from tests.test_parsers.test_gitlab import BULK_ACCESS_MD, LFI_MD, THREAT_PATH, VULN_PATH

REPO_URL = "https://gitlab.com/gitlab-security-oss/tldr.git"


@pytest.fixture
def normalizer():
    return GitLabNormalizer(REPO_URL)


@pytest.fixture
def rows(normalizer):
    parsed = GitLabParser().parse_all(THREAT_PATH, BULK_ACCESS_MD)
    return {p.extra["id"][:1]: normalizer.normalize(p) for p in parsed}


def test_rows_of_one_file_have_distinct_ids(rows):
    assert len({d.id for d in rows.values()}) == 4
    # The path-derived fallback id must differ too: four rules share a file.
    assert len({d.legacy_id for d in rows.values()}) == 4
    assert {d.source_file for d in rows.values()} == {str(THREAT_PATH)}


def test_ids_are_stable(normalizer, rows):
    again = normalizer.normalize(GitLabParser().parse_all(THREAT_PATH, BULK_ACCESS_MD)[0])
    assert again.id == rows["1"].id
    assert rows["1"].rule_id == "11111111-1111-4111-8111-111111111111"


def test_core_fields(rows):
    d = rows["1"]
    assert d.source == "gitlab"
    assert d.language == "sigma"
    assert d.status == "experimental"
    assert d.severity == "low"  # Sigma informational
    assert d.author == "Example Author"
    assert d.mitre_techniques == ["T1213.003"]
    assert d.mitre_tactics == ["TA0009"]
    assert d.use_cases == ["Data exfiltration", "Some new scenario"]
    assert d.rule_created_date.isoformat().startswith("2026-10-01")
    assert d.rule_modified_date.isoformat().startswith("2026-11-02")
    assert d.detection_logic.startswith("selection:\n")
    assert d.investigation_guide.startswith("# About")
    assert d.deploy_notes.startswith("**Applies to:**")
    assert d.false_positives and d.references


def test_modalities(rows):
    assert rows["1"].is_building_block is True and rows["1"].rule_modality == "building_block"
    assert rows["2"].is_building_block is False and rows["2"].rule_modality == "rule"
    assert rows["3"].rule_modality == "correlation" and rows["3"].is_building_block is False
    assert rows["4"].rule_modality == "correlation"
    assert rows["3"].detection_logic.startswith("correlation:\n")


@pytest.mark.parametrize("service, data_source, event_type", [
    ("audit_json.log", "gitlab_audit", "audit_event"),
    ("production_json.log", "gitlab_production", "http_request"),
    ("api_json.log", "gitlab_api", "api_call"),
    ("graphql_json.log", "gitlab_api", "api_call"),
    ("application_json.log", "gitlab_application", "audit_event"),
    ("exceptions_json.log", "gitlab_application", "audit_event"),
    ("workhorse", "gitlab_service_logs", "http_request"),
    ("gitaly", "gitlab_service_logs", "audit_event"),
    ("sidekiq", "gitlab_service_logs", "audit_event"),
    ("puma_stderr", "gitlab_service_logs", "audit_event"),
    # Case and padding in the upstream value must not cause a miss.
    (" API_JSON.log ", "gitlab_api", "api_call"),
])
def test_taxonomy_by_service(service, data_source, event_type):
    parsed = ParsedRule(
        source="gitlab", file_path="x.md", raw_content="", title="t", detection_logic_raw={},
        log_source={"product": "gitlab", "service": service, "services": [service]},
    )
    out = resolve_for_repo("gitlab", parsed)
    assert out["platforms"] == ["gitlab"]
    assert out["data_sources"] == [data_source]
    assert out["event_types"] == [event_type]
    assert out["matched"] is True


@pytest.mark.parametrize("service", [
    "brand_new.log",
    # Near misses of a known service are NOT that service.
    "api_json.log.1", "api_json", "audit_json.log.bak",
])
def test_unlisted_service_is_gitlab_with_no_data_source(service):
    parsed = ParsedRule(
        source="gitlab", file_path="x.md", raw_content="", title="t", detection_logic_raw={},
        log_source={"product": "gitlab", "service": service, "services": [service]},
    )
    out = resolve_for_repo("gitlab", parsed)
    assert out["platforms"] == ["gitlab"]
    assert out["data_sources"] == ["unknown"]
    assert out["fingerprint"] == f"gitlab:{service}"


def test_split_taxonomy_lands_on_devops_and_gitlab(rows):
    d = rows["1"]
    assert d.data_sources == ["gitlab_api"]
    assert d.event_types == ["api_call"]
    assert d.domains == ["devops"]
    assert d.products == ["gitlab"]
    assert d.taxonomy_matched is True
    assert d.taxonomy_fingerprint == "gitlab:api_json.log"


def test_correlation_unions_the_logs_of_its_base_rules(rows):
    d = rows["3"]
    assert d.data_sources == ["gitlab_api", "gitlab_production"]
    assert d.event_types == ["api_call", "http_request"]
    assert d.taxonomy_fingerprint == "gitlab:api_json.log,production_json.log"
    # ... and reads their fields plus the ones it groups and counts by.
    for name in ("route", "controller", "username", "meta.project"):
        assert name in d.extracted_fields_used
    assert d.query_complexity in ("moderate", "complex")


def test_api_actions_are_routes_controllers_and_events_not_rails_verbs(rows):
    assert rows["1"].extracted_api_actions == ["/api/:version/projects/:id/repository/archive"]
    assert rows["2"].extracted_api_actions == ["Repositories::GitHttpController"]
    by_field = {o["field"]: (o["type"], o["subtype"]) for o in rows["2"].extracted_observables}
    assert by_field["controller"] == ("cloud", "api_action")
    assert by_field["action"] == ("event", "event_action")
    assert "git_upload_pack" not in rows["2"].extracted_api_actions


def test_generic_field_names_are_not_read_as_other_products(rows):
    by_field = {o["field"]: (o["type"], o["subtype"]) for o in rows["1"].extracted_observables}
    assert by_field["method"] == ("network", "http_method")
    assert by_field["route"] == ("cloud", "api_action")


def test_documentation_range_placeholders_are_not_indicators(rows):
    """198.51.100.0/24 is RFC 5737 space upstream uses for 'your
    addresses here'; it must not surface as a network indicator."""
    assert rows["1"].extracted_network_indicators == []
    assert rows["1"].rule_modality != "indicator_match"


def test_rule_url_uses_the_gitlab_blob_route_and_encodes_spaces(rows):
    url = rows["1"].source_rule_url
    assert url == (
        "https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/"
        "Detections/platforms/GitLab/Threat%20Detections/bulk_access.md"
    )


def test_pinned_rule_url_round_trips_through_upstream_refs(normalizer, monkeypatch):
    sha = "a" * 40

    class _Git:
        def head_sha(self):
            return sha

        def get_file_dates(self, _path):
            return None, None

    monkeypatch.setattr(normalizer, "_git_service", _Git())
    d = normalizer.normalize(GitLabParser().parse_all(VULN_PATH, LFI_MD)[0])
    assert f"/-/blob/{sha}/Detections/" in d.source_rule_url
    assert pinned_commit(d.source_rule_url) == sha
    assert latest_upstream_url("gitlab", d.source_rule_url) == (
        "https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/"
        "Detections/platforms/GitLab/Vulnerability%20Detections/lfi_probe.md"
    )


def test_embedded_samples_and_atomic_test_count_as_test_evidence(rows):
    d = rows["1"]
    assert d.test_evidence == ["sample_events", "atomic_test"]
    _, details = score_detection(d)
    issues = details["dimensions"]["testability"]["issues"]
    assert "no embedded test cases" not in issues
    assert "no Atomic Red Team reference" not in issues


def test_no_evidence_no_credit(normalizer):
    d = normalizer.normalize(GitLabParser().parse_all(VULN_PATH, LFI_MD)[0])
    assert d.test_evidence == ["sample_events"]
    _, details = score_detection(d)
    assert "no Atomic Red Team reference" in details["dimensions"]["testability"]["issues"]


def test_vulnerability_row(normalizer):
    d = normalizer.normalize(GitLabParser().parse_all(VULN_PATH, LFI_MD)[0])
    assert d.severity == "high"
    assert "cve.2099-0001" in d.tags and "tldr.vulnerability" in d.tags
    assert d.references == ["https://example.com/advisory/CVE-2099-0001"]
    assert d.mitre_techniques == ["T1190"]
