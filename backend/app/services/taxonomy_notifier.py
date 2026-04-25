"""Taxonomy drift notifier — opens/updates GitHub issues on unmapped rules.

This is the Layer 3 observability piece from Issue 2. When the worker
finishes a sync, it calls `notify_drift()` with the per-repo results.
Any repo that has one or more unmapped rules (taxonomy resolver fell
through to UNKNOWN for every dimension) gets a GitHub issue opened or
updated with the fingerprint breakdown + sample rule IDs.

Design choices:

- **No frontend surfacing.** Coverage signals are operational, not
  user-facing. The public site shows the normalized taxonomy as-is.
  Detection Explorer engineers see drift via GitHub issues — their
  existing triage inbox.

- **One issue per repo, reused across syncs.** Title is stable
  (`[taxonomy-drift] <repo>`). If a matching open issue already exists,
  we post a comment with the latest findings instead of opening a new
  one. Closed issues are ignored (engineer consciously closed them —
  let the next drift reopen a fresh one).

- **Feature flag off by default.** Controlled by
  `settings.taxonomy_notifications_enabled`. The GitHub PAT
  (`settings.github_token`) is a separate gate — if either is missing
  the notifier no-ops silently so local dev + tests never reach out to
  GitHub by accident.

- **Failures never block the sync.** Any HTTP error logs a warning and
  returns; the sync job still completes successfully. Taxonomy drift
  is informational, not a hard failure.
"""

import logging
from datetime import datetime
from typing import Optional

import httpx

from app.config import settings
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_ISSUE_TITLE_PREFIX = "[taxonomy-drift]"


async def notify_drift(repo_results: dict, sync_job_id: str) -> None:
    """Emit drift signals for each repo with unmapped rules.

    Args:
        repo_results: The `sync_job.repository_results` dict. Each value
            is expected to have `taxonomy_matched`, `taxonomy_unmatched`,
            `taxonomy_coverage_percent`, and
            `taxonomy_unmatched_by_fingerprint` keys.
        sync_job_id: The sync job's UUID — included in the issue body
            so an engineer can cross-reference against logs.

    The function always returns None. Failures (missing config, HTTP
    errors, etc.) are logged but never raised.
    """
    if not settings.taxonomy_notifications_enabled:
        logger.debug("Taxonomy notifications disabled — skipping drift notify")
        return

    if not settings.github_token:
        logger.info(
            "Taxonomy notifications enabled but no GITHUB_TOKEN configured — skipping"
        )
        return

    if not settings.github_repo_owner or not settings.github_repo_name:
        logger.warning(
            "Taxonomy notifications enabled but GITHUB_REPO_OWNER/NAME missing — skipping"
        )
        return

    drift_repos = [
        (name, result)
        for name, result in repo_results.items()
        if isinstance(result, dict) and result.get("taxonomy_unmatched", 0) > 0
    ]

    if not drift_repos:
        logger.info("No taxonomy drift detected — no issues to open")
        return

    async with httpx.AsyncClient(
        base_url=_GITHUB_API,
        headers={
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30.0,
    ) as client:
        for repo_name, result in drift_repos:
            try:
                await _notify_repo_drift(client, repo_name, result, sync_job_id)
            except Exception as e:
                # Isolate failures per repo so one broken call doesn't
                # block the others. Never raise — this is informational.
                logger.warning(
                    f"Failed to notify taxonomy drift for {repo_name}: "
                    f"{type(e).__name__}: {e}"
                )


async def _notify_repo_drift(
    client: httpx.AsyncClient,
    repo_name: str,
    result: dict,
    sync_job_id: str,
) -> None:
    """Open or update the drift issue for a single repo."""
    owner = settings.github_repo_owner
    repo = settings.github_repo_name
    title = f"{_ISSUE_TITLE_PREFIX} {repo_name}"
    body = _format_drift_body(repo_name, result, sync_job_id)

    existing = await _find_open_issue(client, owner, repo, title)
    if existing is not None:
        await _post_comment(client, owner, repo, existing, body)
        logger.info(
            f"Posted taxonomy drift comment on #{existing} for {repo_name} "
            f"({result['taxonomy_unmatched']} unmapped)"
        )
        return

    number = await _create_issue(client, owner, repo, title, body)
    logger.info(
        f"Opened taxonomy drift issue #{number} for {repo_name} "
        f"({result['taxonomy_unmatched']} unmapped)"
    )


async def _find_open_issue(
    client: httpx.AsyncClient, owner: str, repo: str, title: str
) -> Optional[int]:
    """Return the issue number of an open issue with this exact title, or None."""
    # GitHub's search API is eventually consistent but good enough for
    # once-per-sync dedup. We filter client-side on exact title match
    # since GitHub's `in:title` is a substring search.
    query = f'repo:{owner}/{repo} is:issue is:open "{title}" in:title'
    response = await client.get("/search/issues", params={"q": query, "per_page": 20})
    response.raise_for_status()
    items = response.json().get("items", [])
    for item in items:
        if item.get("title", "").strip() == title:
            return item.get("number")
    return None


async def _create_issue(
    client: httpx.AsyncClient, owner: str, repo: str, title: str, body: str
) -> int:
    """Create a new issue and return its number."""
    response = await client.post(
        f"/repos/{owner}/{repo}/issues",
        json={"title": title, "body": body, "labels": ["taxonomy", "drift"]},
    )
    response.raise_for_status()
    return response.json()["number"]


async def _post_comment(
    client: httpx.AsyncClient, owner: str, repo: str, issue_number: int, body: str
) -> None:
    """Post a comment on an existing issue."""
    response = await client.post(
        f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        json={"body": body},
    )
    response.raise_for_status()


def _format_drift_body(repo_name: str, result: dict, sync_job_id: str) -> str:
    """Build the markdown body for a drift issue or comment."""
    unmapped = result.get("taxonomy_unmatched", 0)
    matched = result.get("taxonomy_matched", 0)
    coverage = result.get("taxonomy_coverage_percent", 0.0)
    total = unmapped + matched
    fingerprints = result.get("taxonomy_unmatched_by_fingerprint", {}) or {}

    # Sort fingerprints by count descending — most common misses first
    sorted_fps = sorted(
        fingerprints.items(),
        key=lambda kv: kv[1].get("count", 0),
        reverse=True,
    )

    lines = [
        f"**Sync job:** `{sync_job_id}`",
        f"**Timestamp (UTC):** {utcnow().isoformat()}",
        f"**Repo:** `{repo_name}`",
        "",
        f"- Rules normalized: **{total}**",
        f"- Rules mapped: **{matched}**",
        f"- Rules unmapped: **{unmapped}**",
        f"- Coverage: **{coverage:.1f}%**",
        "",
        "## Unmapped logsource fingerprints",
        "",
        f"Edit `backend/app/services/taxonomy/mappings/{repo_name}.yaml` to add coverage.",
        "",
        "| Count | Fingerprint | Sample rule |",
        "| ---: | :--- | :--- |",
    ]

    for fp, bucket in sorted_fps[:30]:
        count = bucket.get("count", 0)
        samples = bucket.get("samples") or []
        sample_str = "—"
        if samples:
            s = samples[0]
            title = (s.get("title") or "").replace("|", "\\|")
            rule_id = s.get("rule_id") or s.get("source_file") or "?"
            sample_str = f"`{rule_id}` — {title[:80]}"
        fp_display = fp.replace("|", "\\|") if fp else "-"
        lines.append(f"| {count} | `{fp_display}` | {sample_str} |")

    if len(sorted_fps) > 30:
        lines.append("")
        lines.append(f"_…and {len(sorted_fps) - 30} more fingerprints._")

    return "\n".join(lines)
