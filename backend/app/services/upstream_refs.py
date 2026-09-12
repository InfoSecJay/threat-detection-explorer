"""Where each source's rules live upstream (DX-15 / #157).

One map from source name to the branch we clone, and the helpers that
turn a rule's pinned blob URL back into the moving one.

The normalizers pin ``source_rule_url`` to the commit that was indexed
(``/blob/<sha>/<path>``), so a license review or a diff happens against
the file the catalog actually parsed, not whatever the branch holds
today. The API derives "latest on <branch>" from the pinned link with
``latest_upstream_url``. The methodology page prints the same branch
names, so the table can no longer disagree with the links (the review
found elastic listed as ``master`` while its links went to ``main``, and
splunk listed as ``master`` while its links went to ``develop``).

Verified against the local clones (``git symbolic-ref
refs/remotes/origin/HEAD``) and the GitHub API on 2026-09-11. Every
source in ``ALL_REPOSITORY_NAMES`` must be listed; a test enforces it.
This module imports nothing from the app so the API schema, the sync
service and the normalizers can all use it without a cycle.
"""

from __future__ import annotations

import re
from typing import Optional

REPO_BRANCHES: dict[str, str] = {
    "sigma": "master",
    "elastic": "main",
    "splunk": "develop",
    "sublime": "main",
    "elastic_protections": "main",
    "lolrmm": "main",
    "elastic_hunting": "main",
    "sentinel": "master",
    "google_secops": "main",
    "okta": "master",
    "auth0": "main",
    "panther": "develop",
    "pypanther": "main",
}

_PINNED_BLOB = re.compile(r"/blob/([0-9a-f]{40})/")


def branch_for(source: str) -> str:
    """The branch a source is cloned from; ``master`` for anything unlisted
    (the legacy default the sparse-clone path always used)."""
    return REPO_BRANCHES.get(source, "master")


def pinned_commit(url: Optional[str]) -> Optional[str]:
    """The 40-hex commit a ``/blob/<sha>/`` URL is pinned to; None for a
    branch link (rows indexed before DX-15) or no URL."""
    m = _PINNED_BLOB.search(url or "")
    return m.group(1) if m else None


def latest_upstream_url(source: str, url: Optional[str]) -> Optional[str]:
    """``/blob/<sha>/path`` -> ``/blob/<branch>/path``.

    None when ``url`` is empty or already a branch link: there is no
    second, different link to offer for those rows.
    """
    if not url:
        return None
    m = _PINNED_BLOB.search(url)
    if not m:
        return None
    return f"{url[:m.start()]}/blob/{branch_for(source)}/{url[m.end():]}"
