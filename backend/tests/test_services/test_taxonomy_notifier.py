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
