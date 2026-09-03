"""Tests for the parse-failure notifier (issue #30).

Mirrors the shape of test_taxonomy_notifier -- pure-logic body
formatter tests + gating tests that assert we never touch the network
when the feature flag / PAT / repo config is missing.
"""

from unittest.mock import patch

import pytest

from app.services.ingestion_errors import ErrorSeverity, ErrorStage, IngestionStats
from app.services.parse_failure_notifier import (
    _SMALL_CORPUS_FLOOR,
    _SUCCESS_THRESHOLD_PCT,
    _format_parse_failure_body,
    notify_parse_failures,
)


# --- What counts as a parse failure -----------------------------------


def test_parse_failures_exclude_advisories_about_stored_rules():
    """Only rules we LOST count toward the threshold (#98, #99).

    The duplicate-rule_id advisory is filed at the NORMALIZE stage but
    the rule is stored under its path-derived id; it dragged
    elastic_protections to 99.47% every night for a week.
    """
    stats = IngestionStats(discovered=4, stored=3)
    stats.add_error("a.toml", ErrorStage.PARSE, "Parser returned None",
                    severity=ErrorSeverity.WARNING)
    stats.add_error("b.toml", ErrorStage.NORMALIZE, "boom")
    stats.add_error("c.toml", ErrorStage.NORMALIZE,
                    "Duplicate upstream rule_id 'x'; this file keeps its path-derived id",
                    severity=ErrorSeverity.WARNING, dropped=False)
    stats.add_error("d.toml", ErrorStage.STORE, "db down")

    assert [e.file_path for e in stats.parse_failures] == ["a.toml", "b.toml"]
    # The advisory is still visible to humans through the generic counters.
    assert stats.warning_count == 2
    assert stats.errors[2].to_dict()["dropped"] is False


# --- Body formatter ---------------------------------------------------


def test_format_body_includes_counts_and_samples():
    result = {
        "rules_discovered": 1000,
        "rules_stored": 985,
        "parse_failure_samples": [
            {
                "file_path": "rules/win/a.yml",
                "stage": "parse",
                "severity": "warning",
                "message": "unexpected token",
            },
            {
                "file_path": "rules/linux/b.yml",
                "stage": "normalize",
                "severity": "error",
                "message": "missing logsource.product",
            },
        ],
    }
    body = _format_parse_failure_body(
        "sigma", result, "sync-abc", failure_count=15, success_rate=98.5
    )
    assert "sync-abc" in body
    assert "sigma" in body
    assert "**1000**" in body   # discovered
    assert "**985**" in body    # stored
    assert "**15**" in body     # failure count
    assert "98.50%" in body     # success rate
    assert "PARSE stage" in body
    assert "NORMALIZE stage" in body
    assert "rules/win/a.yml" in body
    assert "rules/linux/b.yml" in body
    assert "unexpected token" in body


def test_format_body_pipe_escaping():
    """Pipe characters in file names / messages must not break the table."""
    result = {
        "rules_discovered": 500,
        "rules_stored": 490,
        "parse_failure_samples": [
            {
                "file_path": "weird|name.yml",
                "stage": "parse",
                "severity": "warning",
                "message": "error | with pipe",
            },
        ],
    }
    body = _format_parse_failure_body(
        "sigma", result, "sync-1", failure_count=10, success_rate=98.0
    )
    assert "weird\\|name.yml" in body
    assert "error \\| with pipe" in body


def test_format_body_handles_missing_stages():
    """No PARSE, no NORMALIZE -- body still generates."""
    result = {
        "rules_discovered": 100,
        "rules_stored": 99,
        "parse_failure_samples": [],
    }
    body = _format_parse_failure_body(
        "sigma", result, "sync-1", failure_count=1, success_rate=99.0
    )
    # Header sections omitted when the stage has zero samples.
    assert "PARSE stage" not in body
    assert "NORMALIZE stage" not in body
    # But the summary rows still render.
    assert "sync-1" in body


def test_format_body_flags_unknown_stages():
    """A sample from an unexpected stage lands in the 'Other stages' line."""
    result = {
        "rules_discovered": 500,
        "rules_stored": 490,
        "parse_failure_samples": [
            {
                "file_path": "x.yml",
                "stage": "discovery",   # not parse or normalize
                "severity": "warning",
                "message": "?",
            },
        ],
    }
    body = _format_parse_failure_body(
        "sigma", result, "sync-1", failure_count=10, success_rate=98.0
    )
    assert "Other stages: discovery" in body


# --- Gating -----------------------------------------------------------


@pytest.mark.asyncio
async def test_noops_when_feature_flag_off():
    """Feature flag off -> never touch the network."""
    repo_results = {
        "sigma": {
            "sync_success": True,
            "rules_discovered": 1000,
            "parse_failure_count": 50,
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = False
        mock_settings.github_token = "fake"
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_noops_when_token_missing():
    """Flag on, no PAT -> silent no-op."""
    repo_results = {
        "sigma": {
            "sync_success": True,
            "rules_discovered": 1000,
            "parse_failure_count": 50,
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = None
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_noops_when_no_failures():
    """All sources parsed cleanly -> nothing to notify."""
    repo_results = {
        "sigma": {
            "sync_success": True,
            "rules_discovered": 1000,
            "parse_failure_count": 0,
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = "fake"
        mock_settings.github_repo_owner = "owner"
        mock_settings.github_repo_name = "repo"
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_noops_when_success_rate_within_tolerance():
    """A tiny share of failures is tolerated -- don't page."""
    # 4/1000 = 99.6% success, above 99.5% threshold.
    repo_results = {
        "sigma": {
            "sync_success": True,
            "rules_discovered": 1000,
            "parse_failure_count": 4,
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = "fake"
        mock_settings.github_repo_owner = "owner"
        mock_settings.github_repo_name = "repo"
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_noops_for_small_corpus():
    """Small corpora skip threshold -- a single failure = huge percent
    swing and would spam the queue."""
    # Corpus below _SMALL_CORPUS_FLOOR -> even a big percent drop is
    # skipped. Confirms the floor guard actually kicks in.
    small = max(1, _SMALL_CORPUS_FLOOR - 1)
    repo_results = {
        "okta": {
            "sync_success": True,
            "rules_discovered": small,
            "parse_failure_count": small,  # 100% failure but tiny corpus
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = "fake"
        mock_settings.github_repo_owner = "owner"
        mock_settings.github_repo_name = "repo"
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_skips_sync_failed_repos():
    """A repo whose clone failed has no meaningful ingest signal."""
    repo_results = {
        "sigma": {
            "sync_success": False,   # sync failed
            "rules_discovered": 0,
            "parse_failure_count": 100,   # nonsense but shouldn't matter
        }
    }
    with patch("app.services.parse_failure_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = "fake"
        mock_settings.github_repo_owner = "owner"
        mock_settings.github_repo_name = "repo"
        with patch(
            "app.services.parse_failure_notifier.httpx.AsyncClient"
        ) as mock_client:
            await notify_parse_failures(repo_results, "sync-1")
            assert not mock_client.called


# --- Threshold sanity checks ------------------------------------------


def test_threshold_constants_are_sensible():
    """Guardrail: someone bumping the threshold to a silly value trips this."""
    assert 90.0 <= _SUCCESS_THRESHOLD_PCT <= 100.0
    assert _SMALL_CORPUS_FLOOR > 0


# --- Credential failure (#46) -----------------------------------------


@pytest.mark.asyncio
async def test_auth_failure_is_single_loud_warning(monkeypatch, caplog):
    """Expired PAT: one ERROR, one returned warning, stop after first 401."""
    import logging as _logging
    import httpx
    from app.config import settings
    from app.services import parse_failure_notifier as pfn

    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", "expired")
    monkeypatch.setattr(settings, "github_repo_owner", "owner")
    monkeypatch.setattr(settings, "github_repo_name", "repo")

    calls: list[str] = []
    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(401, json={"message": "Bad credentials"})

    transport = httpx.MockTransport(handler)

    def factory(**kw):
        return real_async_client(transport=transport, **kw)

    monkeypatch.setattr(pfn.httpx, "AsyncClient", factory)

    repo_results = {
        "sigma": {
            "sync_success": True, "rules_discovered": 1000,
            "parse_failure_count": 50, "parse_failure_samples": [],
        },
        "splunk": {
            "sync_success": True, "rules_discovered": 1000,
            "parse_failure_count": 40, "parse_failure_samples": [],
        },
    }
    with caplog.at_level(_logging.INFO, logger="app.services.parse_failure_notifier"):
        warnings = await notify_parse_failures(repo_results, "sync-1")

    assert len(calls) == 1
    assert len(warnings) == 1
    assert warnings[0]["code"] == "github_auth_failed"
    assert warnings[0]["source"] == "parse_failure_notifier"
    assert sum(1 for r in caplog.records if r.levelno == _logging.ERROR) == 1
