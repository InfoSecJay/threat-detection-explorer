"""Cloudflare purge (#80 S2.3): no-op without config, one POST with the
purge-everything body when configured, and a job-level warning (never an
exception) when the edge says no."""

import httpx
import pytest

from app.config import settings
from app.services import cloudflare as cf


def _install(monkeypatch, handler):
    real = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(**kw):
        return real(transport=transport, **kw)

    monkeypatch.setattr(cf.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_noop_without_config(monkeypatch):
    monkeypatch.setattr(settings, "cloudflare_api_token", None)
    monkeypatch.setattr(settings, "cloudflare_zone_id", None)
    calls = []
    _install(monkeypatch, lambda r: calls.append(r) or httpx.Response(200, json={"success": True}))
    assert await cf.purge_everything() is None
    assert calls == []


@pytest.mark.asyncio
async def test_purges_the_zone_with_bearer_token(monkeypatch):
    monkeypatch.setattr(settings, "cloudflare_api_token", "tok")
    monkeypatch.setattr(settings, "cloudflare_zone_id", "zone123")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200, json={"success": True, "errors": [], "result": {"id": "zone123"}})

    _install(monkeypatch, handler)
    assert await cf.purge_everything(reason="test") is None
    assert seen["url"] == "https://api.cloudflare.com/client/v4/zones/zone123/purge_cache"
    assert seen["auth"] == "Bearer tok"
    assert b'"purge_everything"' in seen["body"] and b"true" in seen["body"]


@pytest.mark.asyncio
async def test_failure_is_a_job_warning(monkeypatch):
    monkeypatch.setattr(settings, "cloudflare_api_token", "tok")
    monkeypatch.setattr(settings, "cloudflare_zone_id", "zone123")
    _install(monkeypatch, lambda r: httpx.Response(
        403, json={"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]},
    ))
    w = await cf.purge_everything(reason="sync abc")
    assert w["code"] == cf.WARNING_CODE_PURGE_FAILED and w["source"] == "cloudflare"
    assert "403" in w["message"] and "Authentication error" in w["message"]


@pytest.mark.asyncio
async def test_network_error_is_a_job_warning(monkeypatch):
    monkeypatch.setattr(settings, "cloudflare_api_token", "tok")
    monkeypatch.setattr(settings, "cloudflare_zone_id", "zone123")

    def boom(_r):
        raise httpx.ConnectError("no route")

    _install(monkeypatch, boom)
    w = await cf.purge_everything()
    assert w["code"] == cf.WARNING_CODE_PURGE_FAILED and "ConnectError" in w["message"]
