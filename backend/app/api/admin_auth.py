"""Admin gate for mutating routes (#74 / teardown F05).

The six write endpoints (repo sync/ingest, MITRE refresh, scheduler
trigger) must not exist on the public surface. Each declares
`Depends(require_admin)` and `include_in_schema=False`:

- absent or wrong `X-Admin-Token` -> **404**, indistinguishable from a
  route that does not exist (401 would advertise a lock to pick);
- `ADMIN_TOKEN` unset in the environment -> the routes are dead
  everywhere, which is the safe default for a fresh deployment;
- the spec never mentions them, so /docs and /openapi.json stay
  read-only.

The nightly sync is unaffected: the worker polls the sync_jobs table
directly and never calls these HTTP routes.
"""

from __future__ import annotations

import secrets
from typing import Optional

from fastapi import Header, HTTPException

from app.config import settings

# One 404 body for every failure mode -- same text FastAPI emits for a
# genuinely unknown path.
_NOT_FOUND = HTTPException(status_code=404, detail="Not Found")


async def require_admin(x_admin_token: Optional[str] = Header(default=None)) -> None:
    expected = settings.admin_token
    if not expected or not x_admin_token:
        raise _NOT_FOUND
    if not secrets.compare_digest(str(x_admin_token), str(expected)):
        raise _NOT_FOUND
