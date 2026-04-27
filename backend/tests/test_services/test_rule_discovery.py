"""Regression tests for RuleDiscoveryService — the file-discovery layer
that decides which paths get fed to parsers.

The class of bug this catches: a silent coverage drop when an upstream
repo restructures and our DISCOVERY_PATTERNS no longer matches. Sentinel
shipped this exact bug — root-level ``Detections/`` and ``ASIM/``
directories were silently excluded for weeks because the patterns
list was incomplete. Without these tests, the only signal is a user
saying "hey, where did rule X go?"

Strategy:
  - Build a tiny fixture directory tree per source matching the upstream
    layout (real on-disk files via pytest's tmp_path, empty content —
    discovery doesn't read the files, only walks the tree).
  - Include "trap" files in excluded directories and with wrong
    extensions to verify the filter logic.
  - Patch settings.get_repo_path to point at the fixture root.
  - Assert: discover_rules returns AT LEAST the expected count, includes
    the canonical paths, and EXCLUDES the trap paths.

If a future PR drops a pattern from DISCOVERY_PATTERNS or breaks the
exclude-dirs filter, the relevant per-source test fails with a message
naming the source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings, settings
from app.services.rule_discovery import RuleDiscoveryService


def _touch(root: Path, rels: list[str]) -> None:
    """Create empty files at each relative path under ``root``."""
    for rel in rels:
        full = root / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.touch()


@pytest.fixture
def discovery(monkeypatch, tmp_path):
    """Yield ``(service, build_repo)`` where ``build_repo(source, files)``
    materializes a fixture clone of ``source`` containing ``files``."""
    repos_root = tmp_path / "repos"
    repos_root.mkdir()

    def build_repo(source: str, files: list[str]) -> Path:
        repo = repos_root / source
        repo.mkdir(exist_ok=True)
        _touch(repo, files)
        return repo

    # Settings is a Pydantic BaseSettings instance — its fields are
    # frozen, so monkeypatching the instance fails. Patch the method on
    # the class instead; the singleton picks up the new bound method.
    monkeypatch.setattr(
        Settings, "get_repo_path", lambda self, name: repos_root / name
    )
    return RuleDiscoveryService(), build_repo


# ── Sigma ────────────────────────────────────────────────────────────


def test_discover_sigma(discovery):
    service, build_repo = discovery
    build_repo("sigma", [
        "rules/windows/process_creation/proc_a.yml",
        "rules/linux/auditd/auditd_a.yml",
        # `rules-*` glob — Sigma occasionally uses split rule trees
        "rules-emerging-threats/threat_a.yaml",
        # ── Traps that must NOT be discovered ─────────────────────
        "rules/windows/tests/should_skip.yml",      # exclude_dirs: tests
        "rules/deprecated/old_rule.yml",            # exclude_dirs: deprecated
        "rules/windows/proc_a.txt",                 # wrong extension
        "docs/readme.md",                           # outside rules/
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("sigma")}

    assert len(found) >= 3, f"Expected ≥3 sigma rules, got {found}"
    assert "rules/windows/process_creation/proc_a.yml" in found
    assert "rules/linux/auditd/auditd_a.yml" in found
    assert "rules-emerging-threats/threat_a.yaml" in found
    assert not any("should_skip" in p for p in found)
    assert not any("deprecated" in p for p in found)
    assert not any(p.endswith(".txt") for p in found)
    assert not any(p.endswith(".md") for p in found)


# ── Elastic ──────────────────────────────────────────────────────────


def test_discover_elastic(discovery):
    service, build_repo = discovery
    build_repo("elastic", [
        "rules/windows/cred_access.toml",
        "rules/linux/persist.toml",
        "rules/cross-platform/exec.toml",
        # Building-block rules live under a SIBLING tree —
        # `rules_building_block/` (plural, no underscore prefix). They
        # ARE discovered; the normalizer tags them as building blocks.
        "rules_building_block/network/lateral_movement.toml",
        "rules_building_block/credential/cred_dumping_signal.toml",
        # Traps
        "rules/_deprecated/old.toml",
        "rules/_building_block/bb.toml",            # legacy upstream name
        "rules/tests/test_rule.toml",
        "rules/windows/cred_access.yml",            # wrong extension
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("elastic")}

    assert len(found) >= 5  # 3 regular + 2 building-block
    assert "rules/windows/cred_access.toml" in found
    assert "rules/cross-platform/exec.toml" in found
    assert "rules_building_block/network/lateral_movement.toml" in found
    assert "rules_building_block/credential/cred_dumping_signal.toml" in found
    assert not any("_deprecated" in p for p in found)
    assert not any("rules/_building_block/" in p for p in found)  # legacy dir excluded
    assert not any("/tests/" in p for p in found)
    assert not any(p.endswith(".yml") for p in found)


# ── Splunk ───────────────────────────────────────────────────────────


def test_discover_splunk(discovery):
    service, build_repo = discovery
    build_repo("splunk", [
        "detections/endpoint/windows_powershell.yml",
        "detections/cloud/aws_iam.yml",
        "detections/network/dns_exfil.yaml",
        # Traps
        "detections/deprecated/old.yml",
        "macros/some_macro.yml",                    # outside detections/
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("splunk")}

    assert len(found) >= 3
    assert "detections/endpoint/windows_powershell.yml" in found
    assert "detections/cloud/aws_iam.yml" in found
    assert not any("deprecated" in p for p in found)
    assert not any(p.startswith("macros/") for p in found)


# ── Sublime ──────────────────────────────────────────────────────────


def test_discover_sublime(discovery):
    service, build_repo = discovery
    build_repo("sublime", [
        "detection-rules/attachment/qakbot.yml",
        "detection-rules/headers/spoofed_sender.yml",
        # Traps
        "detection-rules/tests/test_rule.yml",
        "rules/something.yml",                      # not in detection-rules/
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("sublime")}

    assert len(found) >= 2
    assert "detection-rules/attachment/qakbot.yml" in found
    assert "detection-rules/headers/spoofed_sender.yml" in found
    assert not any("/tests/" in p for p in found)
    assert not any(p.startswith("rules/") for p in found)


# ── Elastic Protections ─────────────────────────────────────────────


def test_discover_elastic_protections(discovery):
    service, build_repo = discovery
    build_repo("elastic_protections", [
        "behavior/rules/windows/lsass_handle.toml",
        "behavior/rules/linux/cred_access.toml",
        "behavior/rules/macos/persist.toml",
        # Traps
        "behavior/rules/deprecated/old.toml",
        "behavior/rules/windows/test_rule.toml",  # filename has "test" — should NOT
                                                  # be excluded (not a path component)
        "endpoint/rules/something.toml",           # not under behavior/
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("elastic_protections")}

    assert len(found) >= 4  # 3 happy-path + the test_rule.toml that's NOT excluded
    assert "behavior/rules/windows/lsass_handle.toml" in found
    assert "behavior/rules/linux/cred_access.toml" in found
    assert not any("deprecated" in p for p in found)
    assert not any(p.startswith("endpoint/") for p in found)


# ── LOLRMM ───────────────────────────────────────────────────────────


def test_discover_lolrmm(discovery):
    service, build_repo = discovery
    build_repo("lolrmm", [
        "detections/sigma/AnyDesk.yml",
        "detections/sigma/Atera.yml",
        "detections/sigma/NetSupport.yaml",
        # Traps
        "detections/sigma/tests/test_rule.yml",
        "detections/yaml/AnyDesk.yml",  # not under detections/sigma/
        "yml/AnyDesk.yml",              # the path layout we initially guessed
                                        # wrong in the e2e test — pin it here
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("lolrmm")}

    assert len(found) >= 3
    assert "detections/sigma/AnyDesk.yml" in found
    assert "detections/sigma/NetSupport.yaml" in found
    assert not any("/tests/" in p for p in found)
    assert not any("detections/yaml/" in p for p in found)
    assert not any(p.startswith("yml/") for p in found)


# ── Elastic Hunting ─────────────────────────────────────────────────


def test_discover_elastic_hunting(discovery):
    service, build_repo = discovery
    build_repo("elastic_hunting", [
        "hunting/aws/persist_iam.toml",
        "hunting/okta/auth_anomaly.toml",
        "hunting/windows/process_anomaly.toml",
        # Traps
        "hunting/deprecated/old.toml",
        "rules/something.toml",                     # outside hunting/
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("elastic_hunting")}

    assert len(found) >= 3
    assert "hunting/aws/persist_iam.toml" in found
    assert "hunting/okta/auth_anomaly.toml" in found
    assert not any("deprecated" in p for p in found)
    assert not any(p.startswith("rules/") for p in found)


# ── Sentinel ─────────────────────────────────────────────────────────


def test_discover_sentinel(discovery):
    """Sentinel pulls from FOUR distinct location patterns. Regression
    on this layout already shipped — root-level Detections/ + ASIM/
    were silently excluded for weeks."""
    service, build_repo = discovery
    build_repo("sentinel", [
        # Tier 1: Solutions/<vendor>/Analytic Rules/
        "Solutions/Microsoft Defender/Analytic Rules/mailforward.yaml",
        "Solutions/AWS/Analytic Rules/console_login.yml",
        # Hunting Queries: discovered (can_parse filters at parse time)
        "Solutions/Microsoft Defender/Hunting Queries/lateral.yaml",
        # Tier 2: root-level Detections/<table>/
        "Detections/AuditLogs/account_creation.yaml",
        "Detections/AWSCloudTrail/anomalous_api.yaml",
        # Tier 3: ASIM/
        "ASIM/Network Session/network_anomaly.yaml",
        # Tier 4: Summary rules/
        "Summary rules/aggregate_alerts.yaml",
        # Traps
        "Solutions/Sample/Analytic Rules/skip_me.yaml",  # 'sample' excluded
        "Workbooks/some_workbook.yaml",                  # outside known dirs
        "Solutions/MyVendor/Analytic Rules/test/skip.yaml",  # 'test' dir
    ])
    found = {str(p).replace("\\", "/") for p in service.discover_rules("sentinel")}

    # Six expected paths from the four legitimate location patterns.
    assert len(found) >= 6, f"Expected ≥6 sentinel rules, got {found}"
    assert "Solutions/Microsoft Defender/Analytic Rules/mailforward.yaml" in found
    assert "Detections/AuditLogs/account_creation.yaml" in found
    assert "Detections/AWSCloudTrail/anomalous_api.yaml" in found
    assert "ASIM/Network Session/network_anomaly.yaml" in found
    assert "Summary rules/aggregate_alerts.yaml" in found
    # Traps must NOT appear
    assert not any("Sample" in p for p in found)
    assert not any(p.startswith("Workbooks/") for p in found)
    assert not any("/test/" in p for p in found)


# ── Cross-cutting checks ─────────────────────────────────────────────


def test_unknown_repo_returns_empty(discovery):
    """Unknown source name → empty generator, no crash."""
    service, _ = discovery
    found = list(service.discover_rules("not_a_real_source"))
    assert found == []


def test_missing_repo_path_returns_empty(monkeypatch, tmp_path):
    """If the configured repo path doesn't exist on disk (e.g. clone
    failed), discovery returns empty without crashing."""
    monkeypatch.setattr(
        Settings,
        "get_repo_path",
        lambda self, name: tmp_path / "nonexistent" / name,
    )
    service = RuleDiscoveryService()
    found = list(service.discover_rules("sigma"))
    assert found == []


def test_count_rules_matches_discovery(discovery):
    """count_rules() agrees with discover_rules() — they're the same code path."""
    service, build_repo = discovery
    build_repo("sigma", [
        "rules/windows/a.yml",
        "rules/linux/b.yml",
        "rules/tests/skip.yml",
    ])
    assert service.count_rules("sigma") == len(list(service.discover_rules("sigma")))


def test_all_sources_have_discovery_patterns():
    """Every source in ALL_REPOSITORY_NAMES has a DISCOVERY_PATTERNS
    entry. Catches the drift bug class where a new source gets added
    to the canonical list but not to the discovery service."""
    from app.services.repository_sync import ALL_REPOSITORY_NAMES

    missing = sorted(
        set(ALL_REPOSITORY_NAMES) - set(RuleDiscoveryService.DISCOVERY_PATTERNS)
    )
    assert not missing, (
        f"Sources in ALL_REPOSITORY_NAMES but missing from "
        f"DISCOVERY_PATTERNS: {missing}. New sources must be added to "
        f"both lists."
    )
