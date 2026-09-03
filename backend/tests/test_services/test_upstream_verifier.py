"""Tests for the upstream tree verifier (issue #29).

Focus areas:
  - Glob-to-regex helper honours ** semantics (recursive vs
    single-segment) and matches real DISCOVERY_PATTERNS shapes.
  - Pattern application against a virtual file list produces the same
    set that RuleDiscoveryService would produce on a local clone.
  - Directory-count snapshot rolls up by TOP-level dir.
  - Diff detects NEW / VANISHED / count-changed directories.
  - Repo URL parser handles the `.git` suffix + non-GitHub URLs.
  - Verifier no-ops when the notifier feature flag is off.
  - Verifier tolerates mismatch within threshold + escalates past it.

The GitHub API is mocked with httpx MockTransport — no live calls.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest

from app.services import upstream_verifier as uv


# ── Glob -> regex ────────────────────────────────────────────────────


class TestGlobToRegex:
    def test_recursive_double_star_matches_any_depth(self):
        r = uv._glob_to_regex("rules/**/*.yml")
        assert r.match("rules/x.yml")
        assert r.match("rules/aws/x.yml")
        assert r.match("rules/aws/subaws/x.yml")
        assert not r.match("rules/aws/x.yaml")
        assert not r.match("policies/x.yml")

    def test_single_star_is_single_segment_only(self):
        r = uv._glob_to_regex("detections/*.yml")
        assert r.match("detections/x.yml")
        assert not r.match("detections/sub/x.yml"), (
            "single * must not cross path segments"
        )

    def test_literal_spaces_survive(self):
        r = uv._glob_to_regex("Solutions/**/Analytic Rules/*.yaml")
        assert r.match("Solutions/AWS/Analytic Rules/x.yaml")
        assert r.match("Solutions/A/B/Analytic Rules/x.yaml")

    def test_regex_specials_in_pattern_are_escaped(self):
        # A dot in the literal part of the glob must not act as regex `.`
        r = uv._glob_to_regex("*.yml")
        assert r.match("x.yml")
        assert not r.match("xxyml"), "'.' must not match arbitrary chars"


# ── Pattern application ──────────────────────────────────────────────


class TestApplyPatterns:
    def test_filters_by_include_and_exclude(self):
        files = [
            "rules/win/a.yml",
            "rules/win/b.yml",
            "rules/deprecated/c.yml",   # excluded by dir
            "rules/tests/d.yml",         # excluded by dir
            "policies/aws.yml",          # not in include
        ]
        got = uv._apply_patterns(
            files,
            include_patterns=["rules/**/*.yml"],
            exclude_dirs={"deprecated", "tests"},
        )
        assert set(got) == {"rules/win/a.yml", "rules/win/b.yml"}

    def test_exclude_dir_check_is_case_insensitive(self):
        files = ["rules/Deprecated/a.yml", "rules/TESTS/b.yml"]
        got = uv._apply_patterns(
            files, include_patterns=["rules/**/*.yml"],
            exclude_dirs={"deprecated", "tests"},
        )
        assert got == []


# ── Directory counts + diff ──────────────────────────────────────────


class TestDirectoryCounts:
    def test_rolls_up_by_top_level(self):
        counts = uv._directory_counts([
            "rules/a/x.yml", "rules/a/y.yml", "rules/b/z.yml",
            "hunting/hq.yml",
        ])
        assert counts == {"rules": 3, "hunting": 1}

    def test_root_files_bucket_as_dot(self):
        assert uv._directory_counts(["deprecated.txt"]) == {".": 1}

    def test_diff_returns_empty_without_previous(self):
        assert uv._diff_directory_counts({"rules": 5}, None) == {}
        assert uv._diff_directory_counts({"rules": 5}, {}) == {}

    def test_diff_flags_new_directory(self):
        diffs = uv._diff_directory_counts(
            {"rules": 5, "rules-dfir": 12},   # rules-dfir is new
            {"rules": 5},
        )
        assert "rules-dfir" in diffs
        assert diffs["rules-dfir"]["kind"] == "new"
        assert diffs["rules-dfir"]["count"] == 12

    def test_diff_flags_vanished_directory(self):
        diffs = uv._diff_directory_counts(
            {"rules": 5},
            {"rules": 5, "detections": 8},
        )
        assert diffs["detections"]["kind"] == "vanished"
        assert diffs["detections"]["previous_count"] == 8

    def test_diff_ignores_small_count_changes(self):
        """<20% jitter shouldn't flag."""
        assert uv._diff_directory_counts({"rules": 105}, {"rules": 100}) == {}

    def test_diff_flags_large_count_changes(self):
        diffs = uv._diff_directory_counts({"rules": 60}, {"rules": 100})
        assert "rules" in diffs
        assert diffs["rules"]["kind"] == "count_changed"
        assert diffs["rules"]["change_pct"] == -40.0


# ── Repo URL parser ─────────────────────────────────────────────────


class TestOwnerRepoParser:
    def test_strips_git_suffix(self):
        assert uv._owner_repo_from_url(
            "https://github.com/SigmaHQ/sigma.git"
        ) == ("SigmaHQ", "sigma")

    def test_no_git_suffix(self):
        assert uv._owner_repo_from_url(
            "https://github.com/panther-labs/panther-analysis"
        ) == ("panther-labs", "panther-analysis")

    def test_non_github_url_returns_none(self):
        assert uv._owner_repo_from_url("https://gitlab.com/x/y.git") is None


# ── Verifier orchestration (with mocked GitHub API) ─────────────────


def _mock_transport(handler):
    """Wrap a handler function into an httpx MockTransport."""
    return httpx.MockTransport(handler)


def _install_mock_client(monkeypatch, handler):
    """Install a mock httpx.AsyncClient that routes all HTTP through
    `handler`. Captures the REAL AsyncClient class first so the mock
    factory doesn't recurse into itself when it constructs the client
    (which would double-pass the `transport=` kwarg and TypeError)."""
    real_async_client = httpx.AsyncClient
    transport = _mock_transport(handler)

    def factory(**kw):
        return real_async_client(transport=transport, **kw)

    monkeypatch.setattr(uv.httpx, "AsyncClient", factory)


def _github_ok_handler(
    tree_files: list[str],
    branch: str = "master",
) -> Any:
    """Handler that emulates the three GitHub calls we make.

    `branch` is the repo's default branch; asking for any other branch
    is a 404, the way GitHub answers for a branch that does not exist.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if re.fullmatch(r"/repos/[^/]+/[^/]+", path):
            return httpx.Response(200, json={"default_branch": branch})
        if path.startswith("/repos/") and "/branches/" in path:
            if path.rsplit("/", 1)[1] != branch:
                return httpx.Response(404, json={"message": "Branch not found"})
            return httpx.Response(200, json={
                "commit": {"commit": {"tree": {"sha": "fake-tree-sha"}}},
            })
        if path.startswith("/repos/") and "/git/trees/" in path:
            return httpx.Response(200, json={
                "tree": [{"path": p, "type": "blob"} for p in tree_files],
            })
        # Any other call (search, issue create) — return empty success.
        if path == "/search/issues":
            return httpx.Response(200, json={"items": []})
        return httpx.Response(200, json={"number": 999})

    return handler


@pytest.mark.asyncio
async def test_verify_noops_when_feature_flag_off(monkeypatch):
    """Whole subsystem is gated on `taxonomy_notifications_enabled`."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", False)

    repo_results = {"sigma": {"sync_success": True, "rules_discovered": 100}}
    await uv.verify_upstream(repo_results, "job-123")

    # Nothing added — flag was off.
    assert "upstream_verification_status" not in repo_results["sigma"]


@pytest.mark.asyncio
async def test_verify_marks_ok_when_counts_match(monkeypatch):
    """Match within threshold -> status: ok, no notification triggered."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)  # never actually alerts

    # Fake upstream tree — 3 rule files under sigma's discovery pattern.
    tree = [
        "rules/windows/a.yml", "rules/windows/b.yml", "rules/linux/c.yml",
        "README.md",  # excluded by pattern
    ]

    _install_mock_client(monkeypatch, _github_ok_handler(tree))

    repo_results = {
        "sigma": {"sync_success": True, "rules_discovered": 3},
    }
    await uv.verify_upstream(repo_results, "job-abc")
    assert repo_results["sigma"]["upstream_verification_status"] == "ok"
    assert repo_results["sigma"]["upstream_expected_count"] == 3
    assert repo_results["sigma"]["upstream_actual_count"] == 3


@pytest.mark.asyncio
async def test_verify_full_clone_follows_upstream_default_branch(monkeypatch):
    """A fully-cloned repo that renamed master -> main still verifies.

    Regression: the verifier used to hardcode `master`, and GitHub's
    301 to `main` surfaced as one WARNING per renamed repo every
    night (elastic, splunk, sublime, lolrmm, auth0, ...).
    """
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    tree = ["rules/windows/a.yml", "rules/windows/b.yml"]
    _install_mock_client(monkeypatch, _github_ok_handler(tree, branch="main"))

    repo_results = {"sigma": {"sync_success": True, "rules_discovered": 2}}
    await uv.verify_upstream(repo_results, "job-abc")
    assert repo_results["sigma"]["upstream_verification_status"] == "ok"


@pytest.mark.asyncio
async def test_verify_sparse_clone_uses_pinned_branch(monkeypatch):
    """Sparse clones verify the branch they checked out, not remote HEAD.

    Panther is sparse-cloned from `develop` while GitHub reports `main`
    as the default; the tree we compare against must be `develop`.
    """
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    branches_requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if re.fullmatch(r"/repos/[^/]+/[^/]+", path):
            return httpx.Response(200, json={"default_branch": "main"})
        if "/branches/" in path:
            branches_requested.append(path.rsplit("/", 1)[1])
        return _github_ok_handler([], branch="develop")(request)

    _install_mock_client(monkeypatch, handler)

    repo_results = {"panther": {"sync_success": True, "rules_discovered": 0}}
    await uv.verify_upstream(repo_results, "job-abc")
    assert branches_requested == ["develop"]
    assert repo_results["panther"]["upstream_verification_status"] == "ok"


@pytest.mark.asyncio
async def test_verify_flags_mismatch_past_threshold(monkeypatch):
    """A meaningful mismatch marks status:mismatch."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    tree = [f"rules/x/{i}.yml" for i in range(100)]

    _install_mock_client(monkeypatch, _github_ok_handler(tree))

    repo_results = {
        "sigma": {"sync_success": True, "rules_discovered": 50},   # 50% off
    }
    await uv.verify_upstream(repo_results, "job-abc")
    assert repo_results["sigma"]["upstream_verification_status"] == "mismatch"


@pytest.mark.asyncio
async def test_verify_skips_when_sync_failed(monkeypatch):
    """Repos whose clone failed don't get verified — nothing to check."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    repo_results = {
        "sigma": {"sync_success": False, "rules_discovered": 0},
    }
    await uv.verify_upstream(repo_results, "job-abc")
    assert repo_results["sigma"]["upstream_verification_status"] == "skipped"


@pytest.mark.asyncio
async def test_verify_isolates_per_repo_failures(monkeypatch):
    """A GitHub API error for one repo doesn't stop others from being verified."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    def handler(request: httpx.Request) -> httpx.Response:
        # Blow up for sigma; succeed for sublime.
        if "SigmaHQ" in request.url.path or "sigma" in request.url.path.lower():
            return httpx.Response(500, json={"message": "boom"})
        return _github_ok_handler(["detection-rules/x.yml"])(request)

    _install_mock_client(monkeypatch, handler)

    repo_results = {
        "sigma":   {"sync_success": True, "rules_discovered": 100},
        "sublime": {"sync_success": True, "rules_discovered": 1},
    }
    await uv.verify_upstream(repo_results, "job-abc")
    # Sigma errored, sublime succeeded — verifier isolates per-repo failures.
    assert repo_results["sigma"]["upstream_verification_status"] == "error"
    assert repo_results["sublime"]["upstream_verification_status"] in ("ok", "mismatch")


@pytest.mark.asyncio
async def test_verify_diffs_directories_vs_previous(monkeypatch):
    """Previous run's directory_counts are consumed to flag drift."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)

    # Current tree has TWO top-level dirs matched (rules + rules-dfir).
    tree = [
        "rules/windows/a.yml",
        "rules/linux/b.yml",
        "rules-dfir/incident/c.yml",   # brand new
    ]

    _install_mock_client(monkeypatch, _github_ok_handler(tree))

    repo_results = {
        "sigma": {"sync_success": True, "rules_discovered": 3},
    }
    previous_results = {
        "sigma": {"upstream_directory_counts": {"rules": 2}},
    }
    await uv.verify_upstream(repo_results, "job-abc", previous_results)

    diffs = repo_results["sigma"]["upstream_directory_diffs"]
    assert "rules-dfir" in diffs
    assert diffs["rules-dfir"]["kind"] == "new"
    # Directory drift alone flips status to mismatch even if counts match.
    assert repo_results["sigma"]["upstream_verification_status"] == "mismatch"


# -- Credential failure (#46) ----------------------------------------


@pytest.mark.asyncio
async def test_verify_auth_failure_is_loud_and_short_circuits(monkeypatch, caplog):
    """An expired GITHUB_TOKEN used to be N per-repo WARNINGs and nothing
    else. Now: ONE ERROR, one job-level warning returned, first repo
    marked auth_error, remaining repos marked auth_error WITHOUT another
    GitHub round-trip."""
    import logging as _logging
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", "expired-token")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(401, json={"message": "Bad credentials"})

    _install_mock_client(monkeypatch, handler)

    repo_results = {
        "sigma":   {"sync_success": True, "rules_discovered": 100},
        "sublime": {"sync_success": True, "rules_discovered": 1},
        "elastic": {"sync_success": False, "rules_discovered": 0},
        "splunk":  {"sync_success": True, "rules_discovered": 5},
    }
    with caplog.at_level(_logging.INFO, logger="app.services.upstream_verifier"):
        warnings = await uv.verify_upstream(repo_results, "job-abc")

    # Exactly one GitHub call was made -- the rest were short-circuited.
    assert len(calls) == 1
    assert repo_results["sigma"]["upstream_verification_status"] == "auth_error"
    assert repo_results["sublime"]["upstream_verification_status"] == "auth_error"
    assert repo_results["splunk"]["upstream_verification_status"] == "auth_error"
    assert repo_results["elastic"]["upstream_verification_status"] == "skipped"

    assert len(warnings) == 1
    assert warnings[0]["code"] == "github_auth_failed"
    assert warnings[0]["source"] == "upstream_verifier"
    assert "3 repositories skipped" in warnings[0]["message"]

    errors = [r for r in caplog.records if r.levelno == _logging.ERROR]
    assert len(errors) == 1, "auth failure must be reported exactly once"
    assert "401" in errors[0].getMessage()


@pytest.mark.asyncio
async def test_verify_rate_limited_403_stays_per_repo(monkeypatch):
    """A rate-limit 403 is NOT a credential problem: it stays a per-repo
    `error` and does not short-circuit the other repos."""
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", "tok")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0"},
            json={"message": "API rate limit exceeded"},
        )

    _install_mock_client(monkeypatch, handler)

    repo_results = {
        "sigma":   {"sync_success": True, "rules_discovered": 100},
        "sublime": {"sync_success": True, "rules_discovered": 1},
    }
    warnings = await uv.verify_upstream(repo_results, "job-abc")
    assert warnings == []
    assert len(calls) == 2
    assert repo_results["sigma"]["upstream_verification_status"] == "error"
    assert repo_results["sublime"]["upstream_verification_status"] == "error"


@pytest.mark.asyncio
async def test_verify_returns_empty_warnings_on_success(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", None)
    _install_mock_client(monkeypatch, _github_ok_handler(["rules/a.yml"]))
    repo_results = {"sigma": {"sync_success": True, "rules_discovered": 1}}
    assert await uv.verify_upstream(repo_results, "job-abc") == []
