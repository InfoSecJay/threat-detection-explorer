"""Platform split (#103): platforms / domains / products.

The vocabulary tables are the contract: every legacy platform value has
a destination, every canonical data source has a domain (or is
explicitly domain-less), and the split never lets a product leak back
into `platforms`.
"""

from __future__ import annotations

import pytest

from app.normalizers.base import NormalizedDetection
from app.services.taxonomy.canonical import DATA_SOURCES, PLATFORMS, UNKNOWN
from app.services.taxonomy.domains import (
    DATA_SOURCE_DOMAINS,
    DATA_SOURCE_PRODUCTS,
    DOMAINS,
    LEGACY_PLATFORM_FILTERS,
    LEGACY_PLATFORM_SPLIT,
    NO_DOMAIN_SOURCES,
    OS_PLATFORMS,
    split_platforms,
)


def test_every_legacy_platform_value_has_a_destination():
    missing = sorted(p for p in PLATFORMS if p not in LEGACY_PLATFORM_SPLIT)
    assert missing == [], f"raw platform values with no split rule: {missing}"


def test_every_data_source_has_a_domain_or_is_explicitly_domainless():
    unplaced = sorted(d for d in DATA_SOURCES if d not in DATA_SOURCE_DOMAINS and d not in NO_DOMAIN_SOURCES)
    assert unplaced == [], f"data sources with no domain: {unplaced}"
    assert set(DATA_SOURCE_PRODUCTS) == set(DATA_SOURCES)
    for ds, domains in DATA_SOURCE_DOMAINS.items():
        assert all(d in DOMAINS for d in domains), (ds, domains)


def test_platform_vocabulary_is_os_only_and_seven_values():
    assert len(OS_PLATFORMS) == 7
    assert len(DOMAINS) == 8
    # The done-when of #103: crowdstrike (and every other product) exists
    # only as a product, never as a platform.
    for value, (os_hint, _domains, product) in LEGACY_PLATFORM_SPLIT.items():
        platforms, _, products = split_platforms([value], [])
        assert set(platforms) <= set(OS_PLATFORMS), value
        if product:
            assert product in products and product not in platforms, value
    assert split_platforms(["crowdstrike"], [])[0] == ["cross_platform"]


@pytest.mark.parametrize(
    "raw, sources, expected",
    [
        (["windows"], ["sysmon", "windows_security_event_log"], (["windows"], ["endpoint"], ["sysmon"])),
        (["okta"], ["okta_system_log"], (["not_applicable"], ["identity"], ["okta"])),
        (["aws", "kubernetes"], ["aws_eks_audit"], (["container"], ["cloud"], ["aws", "kubernetes"])),
        (["azure"], ["entra_id_signin"], (["not_applicable"], ["identity", "cloud"], ["azure"])),
        (["crowdstrike"], ["crowdstrike_event_streams"], (["cross_platform"], ["endpoint"], ["crowdstrike"])),
        (["windows", "linux", "macos"], ["elastic_defend", "crowdstrike_fdr"],
         (["windows", "linux", "macos"], ["endpoint"], ["elastic_defend", "crowdstrike"])),
        (["network_appliance"], ["palo_alto_firewall"], (["not_applicable"], ["network"], ["palo_alto"])),
        (["email"], ["email_message_metadata"], (["not_applicable"], ["email"], [])),
        (["microsoft_365"], ["m365_exchange_audit"], (["not_applicable"], ["saas", "email"], ["microsoft_365"])),
        (["cross_platform"], ["application_logs"], (["cross_platform"], [UNKNOWN], [])),
        ([UNKNOWN], [UNKNOWN], ([UNKNOWN], [UNKNOWN], [])),
        # A Panther rule that says only windows_event_logs keeps windows via the raw platform.
        (["windows"], ["windows_event_logs"], (["windows"], ["endpoint"], [])),
        # Re-normalizing an already-split row is a no-op.
        (["not_applicable"], ["okta_system_log"], (["not_applicable"], ["identity"], ["okta"])),
    ],
)
def test_split_examples(raw, sources, expected):
    assert split_platforms(raw, sources) == expected


def test_legacy_filter_values_retarget_products_and_domains():
    assert LEGACY_PLATFORM_FILTERS["okta"] == ("products", "okta")
    assert LEGACY_PLATFORM_FILTERS["crowdstrike"] == ("products", "crowdstrike")
    assert LEGACY_PLATFORM_FILTERS["email"] == ("domains", "email")
    assert LEGACY_PLATFORM_FILTERS["network_appliance"] == ("domains", "network")
    assert "windows" not in LEGACY_PLATFORM_FILTERS and "cross_platform" not in LEGACY_PLATFORM_FILTERS


def test_normalized_detection_applies_the_split():
    n = NormalizedDetection(
        id="x", source="panther", source_file="r.yml", source_repo_url="https://x", title="t",
        description="d", author=None,
        detection_logic="q", language="python", raw_content="raw", severity="high", status="stable",
        platforms=["crowdstrike", "aws"], data_sources=["crowdstrike_event_streams", "aws_cloudtrail"],
        event_types=["process_creation"],
    )
    assert n.platforms == ["cross_platform"]
    assert n.domains == ["endpoint", "cloud"]
    assert n.products == ["crowdstrike", "aws"]
