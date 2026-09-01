"""Data-source alias table + near-duplicate gate (teardown R04 / #102).

The methodology page promises one data-source vocabulary. These tests
make that a build gate: alias spellings must resolve to canonical ids,
and no two canonical values may look like alternate spellings of the
same id (the m365_* / microsoft365_* shape that shipped as live facet
twins).
"""

from app.services.taxonomy.canonical import (
    DATA_SOURCE_ALIASES,
    DATA_SOURCE_PLATFORMS,
    DATA_SOURCES,
    canonical_data_source,
    find_near_duplicate_data_sources,
)
from app.services.taxonomy.resolver import resolve_for_repo


class TestAliasTable:
    def test_every_alias_target_is_canonical(self):
        missing = {v for v in DATA_SOURCE_ALIASES.values() if v not in DATA_SOURCES}
        assert not missing, f"alias targets not in DATA_SOURCES: {sorted(missing)}"

    def test_no_alias_key_is_also_canonical(self):
        both = set(DATA_SOURCE_ALIASES) & DATA_SOURCES
        assert not both, f"values cannot be both alias and canonical: {sorted(both)}"

    def test_known_synonym_families_collapse(self):
        assert canonical_data_source("microsoft365_exchange_audit") == "m365_exchange_audit"
        assert canonical_data_source("microsoft_defender_xdr") == "m365_defender"
        assert canonical_data_source("azure_monitor_activity") == "azure_activity"
        assert canonical_data_source("carbon_black_audit") == "carbon_black"
        assert canonical_data_source("carbon_black_alert") == "carbon_black"
        assert canonical_data_source("sentinelone_activity") == "sentinelone"

    def test_canonical_values_pass_through(self):
        assert canonical_data_source("sysmon") == "sysmon"
        assert canonical_data_source("m365_defender") == "m365_defender"

    def test_distinct_defender_products_stay_distinct(self):
        """Collapse synonyms, never products: MDE, Defender for Cloud and
        the Defender AV event log are three feeds, not three spellings."""
        for ds in ("defender_endpoint", "defender_cloud", "windows_defender_event_log"):
            assert ds in DATA_SOURCES
            assert ds not in DATA_SOURCE_ALIASES

    def test_platform_map_carries_no_alias_keys(self):
        stale = set(DATA_SOURCE_PLATFORMS) & set(DATA_SOURCE_ALIASES)
        assert not stale, f"DATA_SOURCE_PLATFORMS keys must be canonical: {sorted(stale)}"


class TestNearDuplicateGate:
    def test_canonical_set_has_no_near_duplicates(self):
        """The build gate itself (B2): fails when a new facet value is a
        prefix-synonym or spelling twin of an existing one."""
        dups = find_near_duplicate_data_sources()
        assert not dups, (
            f"near-duplicate data-source values: {dups} -- "
            "add an alias in DATA_SOURCE_ALIASES instead of a twin value"
        )

    def test_detector_catches_naming_convention_twins(self):
        planted = frozenset({"m365_test_audit", "microsoft365_test_audit"})
        assert find_near_duplicate_data_sources(planted) == [
            ("m365_test_audit", "microsoft365_test_audit")
        ]

    def test_detector_catches_plural_twins(self):
        planted = frozenset({"windows_event_log", "windows_event_logs"})
        assert find_near_duplicate_data_sources(planted)

    def test_detector_catches_prefix_extensions(self):
        planted = frozenset({"carbon_black", "carbon_black_audit"})
        assert find_near_duplicate_data_sources(planted)

    def test_allowlist_suppresses_documented_exceptions(self):
        planted = frozenset({"carbon_black", "carbon_black_audit"})
        assert not find_near_duplicate_data_sources(
            planted, allow=frozenset({"carbon_black|carbon_black_audit"})
        )


class TestResolverCanonicalizes:
    def test_resolver_rewrites_alias_spellings(self, monkeypatch):
        """End to end through resolve_for_repo: a vendor resolver emitting
        an accepted alias spelling stores the canonical id."""
        from app.services.taxonomy import resolver as resolver_mod

        def fake_vendor(parsed):
            return {
                "platforms": ["windows"],
                "data_sources": ["microsoft_defender_xdr", "m365_defender", "sysmon"],
                "event_types": ["process_creation"],
            }

        class FakeParsed:
            log_source = {"product": "windows"}
            tags = []
            extra = {}

        monkeypatch.setitem(resolver_mod._VENDOR_RESOLVERS, "faketest", fake_vendor)
        out = resolve_for_repo("faketest", parsed=FakeParsed())
        assert out["data_sources"].count("m365_defender") == 1
        assert "microsoft_defender_xdr" not in out["data_sources"]
        assert "sysmon" in out["data_sources"]
