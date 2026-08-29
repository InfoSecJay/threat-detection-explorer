"""Tests for the taxonomy drift notifier.

Only covers pure logic — the body formatter and the no-op gating when
config is missing. HTTP-level behavior is exercised by integration
(local runs hit GitHub with a PAT in the env).
"""

from unittest.mock import patch

import pytest

from app.services.taxonomy_notifier import _format_drift_body, notify_drift


def test_format_drift_body_includes_counts_and_fingerprints():
    result = {
        "taxonomy_matched": 80,
        "taxonomy_unmatched": 20,
        "taxonomy_coverage_percent": 80.0,
        "taxonomy_unmatched_by_fingerprint": {
            "sigma:foo/-/bar": {
                "count": 15,
                "samples": [
                    {"rule_id": "rid-1", "source_file": "rules/a.yml", "title": "alpha"},
                ],
            },
            "sigma:baz/-/qux": {
                "count": 5,
                "samples": [
                    {"rule_id": None, "source_file": "rules/b.yml", "title": "beta"},
                ],
            },
        },
    }
    body = _format_drift_body("sigma", result, "abc-123")
    assert "abc-123" in body
    assert "sigma" in body
    assert "**80**" in body  # matched count
    assert "**20**" in body  # unmapped count
    assert "80.0%" in body
    # Fingerprints sorted by count desc — the 15-count entry must appear
    # before the 5-count entry.
    assert body.index("sigma:foo/-/bar") < body.index("sigma:baz/-/qux")
    assert "alpha" in body


def test_format_drift_body_handles_empty_fingerprints():
    result = {
        "taxonomy_matched": 100,
        "taxonomy_unmatched": 0,
        "taxonomy_coverage_percent": 100.0,
        "taxonomy_unmatched_by_fingerprint": {},
    }
    body = _format_drift_body("sigma", result, "abc-123")
    assert "Count" in body  # table header still emitted
    assert "**0**" in body


@pytest.mark.asyncio
async def test_notify_drift_noops_when_disabled():
    """With the feature flag off, notify_drift never touches the network."""
    repo_results = {"sigma": {"taxonomy_unmatched": 10}}
    with patch("app.services.taxonomy_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = False
        mock_settings.github_token = "fake-token"
        with patch("app.services.taxonomy_notifier.httpx.AsyncClient") as mock_client:
            await notify_drift(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_notify_drift_noops_when_token_missing():
    """Feature flag on but no PAT → still a no-op."""
    repo_results = {"sigma": {"taxonomy_unmatched": 10}}
    with patch("app.services.taxonomy_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = None
        with patch("app.services.taxonomy_notifier.httpx.AsyncClient") as mock_client:
            await notify_drift(repo_results, "sync-1")
            assert not mock_client.called


@pytest.mark.asyncio
async def test_notify_drift_noops_when_no_drift():
    """All repos have zero unmapped — nothing to notify, don't touch network."""
    repo_results = {"sigma": {"taxonomy_unmatched": 0, "taxonomy_matched": 100}}
    with patch("app.services.taxonomy_notifier.settings") as mock_settings:
        mock_settings.taxonomy_notifications_enabled = True
        mock_settings.github_token = "fake-token"
        mock_settings.github_repo_owner = "owner"
        mock_settings.github_repo_name = "repo"
        with patch("app.services.taxonomy_notifier.httpx.AsyncClient") as mock_client:
            await notify_drift(repo_results, "sync-1")
            assert not mock_client.called


# --- Credential failure (#46) -----------------------------------------


def _install_mock_client(monkeypatch, handler, module):
    """Route the given module httpx.AsyncClient through a MockTransport."""
    import httpx
    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(**kw):
        return real_async_client(transport=transport, **kw)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


def _drift_results() -> dict:
    return {
        "sigma": {
            "taxonomy_matched": 1, "taxonomy_unmatched": 5,
            "taxonomy_coverage_percent": 16.7,
            "taxonomy_unmatched_by_fingerprint": {},
        },
        "splunk": {
            "taxonomy_matched": 1, "taxonomy_unmatched": 2,
            "taxonomy_coverage_percent": 33.3,
            "taxonomy_unmatched_by_fingerprint": {},
        },
    }


@pytest.mark.asyncio
async def test_notify_drift_auth_failure_is_single_loud_warning(monkeypatch, caplog):
    """Expired PAT: one ERROR, one returned warning, no further per-repo
    attempts after the first 401."""
    import logging as _logging
    import httpx
    from app.config import settings
    from app.services import taxonomy_notifier as tn

    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", "expired")
    monkeypatch.setattr(settings, "github_repo_owner", "owner")
    monkeypatch.setattr(settings, "github_repo_name", "repo")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(401, json={"message": "Bad credentials"})

    _install_mock_client(monkeypatch, handler, tn)

    with caplog.at_level(_logging.INFO, logger="app.services.taxonomy_notifier"):
        warnings = await notify_drift(_drift_results(), "sync-1")

    assert len(calls) == 1, "second repo must not be attempted after a 401"
    assert len(warnings) == 1
    assert warnings[0]["code"] == "github_auth_failed"
    assert warnings[0]["source"] == "taxonomy_notifier"
    assert "2 repositories skipped" in warnings[0]["message"]
    assert sum(1 for r in caplog.records if r.levelno == _logging.ERROR) == 1


@pytest.mark.asyncio
async def test_notify_drift_non_auth_error_stays_per_repo(monkeypatch):
    """A 500 from GitHub is isolated per repo (existing behaviour) and
    yields no job-level warning."""
    import httpx
    from app.config import settings
    from app.services import taxonomy_notifier as tn

    monkeypatch.setattr(settings, "taxonomy_notifications_enabled", True)
    monkeypatch.setattr(settings, "github_token", "tok")
    monkeypatch.setattr(settings, "github_repo_owner", "owner")
    monkeypatch.setattr(settings, "github_repo_name", "repo")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={"message": "boom"})

    _install_mock_client(monkeypatch, handler, tn)

    warnings = await notify_drift(_drift_results(), "sync-1")
    assert warnings == []
    assert len(calls) == 2
