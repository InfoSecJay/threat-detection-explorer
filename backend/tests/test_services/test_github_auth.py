"""Tests for the shared GitHub auth helpers (#46).

Covers:
  - is_auth_error: 401 always; 403 only when NOT rate-limited; other
    statuses and non-HTTP exceptions never.
  - auth_failure_warning: stable {code, source, message} shape.
  - parse_expiry_header: GitHub's "YYYY-MM-DD HH:MM:SS UTC" format,
    absent header, garbage.
  - check_github_token: missing / ok (with expiry + rate limit) /
    invalid / unreachable, via httpx.MockTransport -- no live calls.
  - log_token_status: level selection (ERROR on invalid, WARNING near
    expiry, INFO otherwise).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import settings
from app.services import github_auth as ga


def _status_error(status: int, headers: dict | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.github.com/x")
    response = httpx.Response(status, headers=headers or {}, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


# -- is_auth_error ---------------------------------------------------


class TestIsAuthError:
    def test_401_is_auth_error(self):
        assert ga.is_auth_error(_status_error(401))

    def test_403_without_rate_limit_exhaustion_is_auth_error(self):
        assert ga.is_auth_error(_status_error(403))
        assert ga.is_auth_error(_status_error(403, {"x-ratelimit-remaining": "42"}))

    def test_403_rate_limited_is_not_auth_error(self):
        """Primary rate limiting is also a 403; it must not masquerade
        as an expired token."""
        assert not ga.is_auth_error(_status_error(403, {"x-ratelimit-remaining": "0"}))

    def test_other_statuses_are_not_auth_errors(self):
        for status in (400, 404, 422, 500, 502):
            assert not ga.is_auth_error(_status_error(status)), status

    def test_non_http_exceptions_are_not_auth_errors(self):
        assert not ga.is_auth_error(ValueError("nope"))
        assert not ga.is_auth_error(
            httpx.ConnectError("x", request=httpx.Request("GET", "https://x"))
        )


# -- auth_failure_warning ----------------------------------------------


class TestAuthFailureWarning:
    def test_shape_and_content(self):
        w = ga.auth_failure_warning("upstream_verifier", _status_error(401), affected=11)
        assert w["code"] == ga.WARNING_CODE_AUTH_FAILED
        assert w["source"] == "upstream_verifier"
        assert "401" in w["message"]
        assert "GITHUB_TOKEN" in w["message"]
        assert "11 repositories skipped" in w["message"]

    def test_singular_affected(self):
        w = ga.auth_failure_warning("taxonomy_notifier", _status_error(403), affected=1)
        assert "1 repository skipped" in w["message"]

    def test_no_affected_count_omits_clause(self):
        w = ga.auth_failure_warning("taxonomy_notifier", _status_error(401))
        assert "skipped" not in w["message"]

    def test_non_http_exception_uses_placeholder_status(self):
        w = ga.auth_failure_warning("x", RuntimeError("?"))
        assert "returned ?" in w["message"]


# -- parse_expiry_header ----------------------------------------------


class TestParseExpiryHeader:
    def test_github_format(self):
        got = ga.parse_expiry_header("2027-08-29 04:00:00 UTC")
        assert got == datetime(2027, 8, 29, 4, 0, 0, tzinfo=timezone.utc)

    def test_missing(self):
        assert ga.parse_expiry_header(None) is None
        assert ga.parse_expiry_header("") is None

    def test_garbage(self):
        assert ga.parse_expiry_header("never") is None


# -- check_github_token ------------------------------------------------


def _client_with(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=ga.GITHUB_API,
        transport=httpx.MockTransport(handler),
        headers=ga.github_headers("tok"),
    )


@pytest.mark.asyncio
async def test_check_missing_token(monkeypatch):
    monkeypatch.setattr(settings, "github_token", None)
    status = await ga.check_github_token()
    assert status.state == "missing"
    assert status.days_until_expiry is None


@pytest.mark.asyncio
async def test_check_ok_with_expiry_and_rate_limit(monkeypatch):
    monkeypatch.setattr(settings, "github_token", "tok")
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            headers={"github-authentication-token-expiration": "2027-08-29 04:00:00 UTC"},
            json={"resources": {"core": {"limit": 5000}}},
        )

    async with _client_with(handler) as client:
        status = await ga.check_github_token(client)

    assert seen["path"] == "/rate_limit"
    assert seen["auth"] == "Bearer tok"
    assert status.state == "ok"
    assert status.rate_limit == 5000
    assert status.expires_at == datetime(2027, 8, 29, 4, 0, 0, tzinfo=timezone.utc)
    assert status.days_until_expiry is not None


@pytest.mark.asyncio
async def test_check_ok_without_expiry_header(monkeypatch):
    """Classic PATs never set the expiry header -- still `ok`."""
    monkeypatch.setattr(settings, "github_token", "tok")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"resources": {"core": {"limit": 5000}}})

    async with _client_with(handler) as client:
        status = await ga.check_github_token(client)
    assert status.state == "ok"
    assert status.expires_at is None


@pytest.mark.asyncio
async def test_check_invalid_token(monkeypatch):
    monkeypatch.setattr(settings, "github_token", "expired")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    async with _client_with(handler) as client:
        status = await ga.check_github_token(client)
    assert status.state == "invalid"
    assert "401" in status.detail


@pytest.mark.asyncio
async def test_check_unreachable_on_server_error(monkeypatch):
    monkeypatch.setattr(settings, "github_token", "tok")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with _client_with(handler) as client:
        status = await ga.check_github_token(client)
    assert status.state == "unreachable"


@pytest.mark.asyncio
async def test_check_unreachable_on_network_error(monkeypatch):
    monkeypatch.setattr(settings, "github_token", "tok")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns", request=request)

    async with _client_with(handler) as client:
        status = await ga.check_github_token(client)
    assert status.state == "unreachable"
    assert "ConnectError" in status.detail


# -- log_token_status ---------------------------------------------------


class TestLogTokenStatus:
    def test_invalid_logs_error(self, caplog):
        with caplog.at_level(logging.INFO, logger="app.services.github_auth"):
            ga.log_token_status(ga.TokenStatus(state="invalid", detail="401"))
        assert any(r.levelno == logging.ERROR for r in caplog.records)
        assert "rotated" in caplog.text

    def test_near_expiry_logs_warning(self, caplog):
        now = datetime.now(timezone.utc)
        status = ga.TokenStatus(
            state="ok", expires_at=now + timedelta(days=5), checked_at=now,
        )
        with caplog.at_level(logging.INFO, logger="app.services.github_auth"):
            ga.log_token_status(status)
        assert any(r.levelno == logging.WARNING for r in caplog.records)
        assert "expires in 5 day" in caplog.text

    def test_healthy_logs_info_only(self, caplog):
        now = datetime.now(timezone.utc)
        status = ga.TokenStatus(
            state="ok", expires_at=now + timedelta(days=300), rate_limit=5000,
            checked_at=now,
        )
        with caplog.at_level(logging.INFO, logger="app.services.github_auth"):
            ga.log_token_status(status)
        assert all(r.levelno == logging.INFO for r in caplog.records)
        assert "300 days" in caplog.text

    def test_missing_logs_info(self, caplog):
        with caplog.at_level(logging.INFO, logger="app.services.github_auth"):
            ga.log_token_status(ga.TokenStatus(state="missing"))
        assert all(r.levelno == logging.INFO for r in caplog.records)
        assert "anonymously" in caplog.text
