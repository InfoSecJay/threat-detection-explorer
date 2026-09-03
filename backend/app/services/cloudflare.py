"""Cloudflare edge cache purge (#80 S2.3).

Read routes are cached at the edge for 15 minutes with a day of
stale-while-revalidate, so without a purge the site keeps serving the
previous corpus for a while after the nightly sync lands. The worker
calls ``purge_everything`` once at the end of a completed sync.

No-op unless both CLOUDFLARE_API_TOKEN (a token scoped to Zone ->
Cache Purge on this one zone) and CLOUDFLARE_ZONE_ID are set. Never
raises: a purge failure is a job-level warning, not a failed sync.
Purge-everything is the only mode every Cloudflare plan supports;
prefix and tag purges are Enterprise-only, and the corpus changes as a
whole anyway.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_API = "https://api.cloudflare.com/client/v4"
WARNING_CODE_PURGE_FAILED = "cloudflare_purge_failed"


def is_configured() -> bool:
    return bool(settings.cloudflare_api_token and settings.cloudflare_zone_id)


async def purge_everything(reason: str = "sync") -> Optional[dict]:
    """Purge the whole zone.

    Returns None when not configured or on success, and a job-level
    warning dict (same shape as github_auth.auth_failure_warning) when
    the purge was attempted and failed, so the scheduler can persist it
    on ``sync_jobs.warnings``.
    """
    if not is_configured():
        logger.debug("Cloudflare purge skipped: CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID unset")
        return None

    url = f"{_API}/zones/{settings.cloudflare_zone_id}/purge_cache"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                json={"purge_everything": True},
                headers={"Authorization": f"Bearer {settings.cloudflare_api_token}"},
            )
        body = response.json() if response.content else {}
        if response.status_code == 200 and body.get("success") is True:
            logger.info(f"Cloudflare cache purged ({reason})")
            return None
        detail = (
            f"Cloudflare purge failed ({reason}): HTTP {response.status_code} "
            f"{body.get('errors') or body}"
        )
    except Exception as e:  # noqa: BLE001 -- never let the edge break the sync
        detail = f"Cloudflare purge failed ({reason}): {type(e).__name__}: {e}"

    logger.error(detail)
    return {
        "code": WARNING_CODE_PURGE_FAILED,
        "source": "cloudflare",
        "message": detail[:500],
    }
