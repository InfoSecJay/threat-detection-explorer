"""GitHub API authentication helpers shared by the sync-time notifiers.

Three consumers talk to api.github.com after a sync: the taxonomy-drift
notifier, the parse-failure notifier, and the upstream verifier. All
three used to treat an expired ``GITHUB_TOKEN`` as N per-repo
``WARNING`` lines and otherwise carry on (#46) -- ingestion clones are
anonymous, so nothing else noticed. This module centralises:

- ``github_headers()`` -- the header set every consumer builds.
- ``is_auth_error(exc)`` -- "is this HTTP failure a credential problem?"
  so callers can stop retrying per-repo and raise ONE loud signal.
- ``auth_failure_warning(...)`` -- the job-level warning record that
  lands on ``sync_jobs.warnings`` so ``/api/scheduler/jobs`` shows it.
- ``check_github_token()`` -- a startup probe of ``GET /rate_limit``
  (free: does not count against the quota) that logs the token's
  expiry from the ``github-authentication-token-expiration`` header,
  so rotation can be scheduled instead of discovered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# Warn at startup when the token expires within this many days. Fine-
# grained PATs max out at one year; 30 days is enough notice to rotate
# without being noisy for most of the token's life.
EXPIRY_WARNING_DAYS = 30

# Header GitHub sets on responses authenticated with a PAT that has an
# expiry. Format: "2027-08-29 04:00:00 UTC".
_EXPIRY_HEADER = "github-authentication-token-expiration"

WARNING_CODE_AUTH_FAILED = "github_auth_failed"


def github_headers(token: Optional[str] = None) -> dict[str, str]:
    """Standard header set for api.github.com. Bearer auth only when a
    token is configured -- anonymous calls are still valid (60 req/h)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = settings.github_token if token is None else token
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def is_auth_error(exc: BaseException) -> bool:
    """True when ``exc`` is an HTTP failure caused by bad credentials.

    401 is always a credential problem. 403 is ambiguous: GitHub uses it
    for both "token lacks scope / is revoked" AND primary rate limiting.
    A rate-limited 403 carries ``X-RateLimit-Remaining: 0``; treat that
    as NOT an auth error so a busy hour does not masquerade as an
    expired token.
    """
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    status = exc.response.status_code
    if status == 401:
        return True
    if status == 403:
        remaining = exc.response.headers.get("x-ratelimit-remaining")
        return remaining != "0"
    return False


def auth_failure_warning(
    source: str, exc: BaseException, *, affected: int = 0,
) -> dict:
    """Build the job-level warning record for a credential failure.

    Shape is stable (``code`` / ``source`` / ``message``) so the frontend
    can render it without knowing which subsystem emitted it.
    """
    status = (
        exc.response.status_code
        if isinstance(exc, httpx.HTTPStatusError) else "?"
    )
    detail = (
        f"GitHub API returned {status} for {source}; "
        f"GITHUB_TOKEN on the worker service is missing, expired, or "
        f"lacks scope."
    )
    if affected:
        detail += f" {affected} repositor{'y' if affected == 1 else 'ies'} skipped."
    return {
        "code": WARNING_CODE_AUTH_FAILED,
        "source": source,
        "message": detail,
    }


# -- Startup token probe ------------------------------------------------


@dataclass
class TokenStatus:
    """Result of ``check_github_token``.

    ``state`` is one of:
      - ``missing``      no GITHUB_TOKEN configured (anonymous mode)
      - ``ok``           token authenticates
      - ``invalid``      GitHub rejected it (401/403)
      - ``unreachable``  network / non-auth HTTP failure; nothing learned
    """

    state: str
    expires_at: Optional[datetime] = None
    rate_limit: Optional[int] = None
    detail: str = ""
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def days_until_expiry(self) -> Optional[int]:
        if self.expires_at is None:
            return None
        return (self.expires_at - self.checked_at).days


def parse_expiry_header(value: Optional[str]) -> Optional[datetime]:
    """Parse ``2027-08-29 04:00:00 UTC`` into an aware UTC datetime.

    Returns None when the header is absent or in an unexpected format
    (classic PATs without expiry do not set it at all).
    """
    if not value:
        return None
    raw = value.strip()
    if raw.endswith(" UTC"):
        raw = raw[:-4]
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


async def check_github_token(
    client: Optional[httpx.AsyncClient] = None,
) -> TokenStatus:
    """Probe ``GET /rate_limit`` with the configured token.

    Never raises. The rate_limit endpoint is exempt from the quota, so
    calling it once per worker boot is free.
    """
    if not settings.github_token:
        return TokenStatus(state="missing", detail="GITHUB_TOKEN not configured")

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(
            base_url=GITHUB_API, headers=github_headers(), timeout=15.0,
        )
    try:
        response = await client.get("/rate_limit")
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        if is_auth_error(e):
            return TokenStatus(
                state="invalid",
                detail=f"{e.response.status_code} from GET /rate_limit",
            )
        return TokenStatus(
            state="unreachable",
            detail=f"{e.response.status_code} from GET /rate_limit",
        )
    except Exception as e:  # network errors, timeouts
        return TokenStatus(
            state="unreachable", detail=f"{type(e).__name__}: {e}",
        )
    finally:
        if owns_client:
            await client.aclose()

    expires_at = parse_expiry_header(response.headers.get(_EXPIRY_HEADER))
    rate_limit: Optional[int] = None
    try:
        rate_limit = int(response.json()["resources"]["core"]["limit"])
    except Exception:
        pass
    return TokenStatus(state="ok", expires_at=expires_at, rate_limit=rate_limit)


def log_token_status(status: TokenStatus) -> None:
    """Emit the startup log line at a level matching the finding."""
    if status.state == "missing":
        logger.info(
            "GITHUB_TOKEN not configured -- GitHub notifiers disabled, "
            "upstream verifier runs anonymously (60 req/h)"
        )
        return
    if status.state == "invalid":
        logger.error(
            f"GITHUB_TOKEN rejected by GitHub ({status.detail}). Drift "
            f"notifications and upstream verification will fail every "
            f"sync until the token is rotated on the worker service."
        )
        return
    if status.state == "unreachable":
        logger.warning(
            f"Could not verify GITHUB_TOKEN at startup ({status.detail}); "
            f"will find out at the next sync"
        )
        return

    days = status.days_until_expiry
    if days is None:
        logger.info(
            f"GITHUB_TOKEN OK (rate limit {status.rate_limit}/h, no expiry "
            f"reported)"
        )
    elif days <= EXPIRY_WARNING_DAYS:
        logger.warning(
            f"GITHUB_TOKEN expires in {days} day(s) "
            f"({status.expires_at:%Y-%m-%d}) -- rotate it on the worker "
            f"service before then"
        )
    else:
        logger.info(
            f"GITHUB_TOKEN OK (rate limit {status.rate_limit}/h, expires "
            f"{status.expires_at:%Y-%m-%d}, {days} days)"
        )
