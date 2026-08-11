"""Parse-failure notifier -- opens/updates GitHub issues when ingest
success rate drops below the tolerance threshold (issue #30).

Sibling to `taxonomy_notifier` and `upstream_verifier` -- same feature
flag, same GitHub PAT, same per-source failure isolation. The three
observability layers each cover a distinct failure mode:

  taxonomy_notifier  -> the rule made it through but we couldn't map
                        its logsource to canonical taxonomy
  upstream_verifier  -> upstream file count differs from what we
                        discovered/ingested locally
  parse_failures     -> we discovered the file but PARSE or NORMALIZE
                        threw and we silently dropped the rule

Today Sigma's ingest success rate is 100% (file count == site count).
Any regression from upstream schema drift, YAML edge cases, or a
broken parser change lands as an ErrorStage.PARSE / NORMALIZE entry
that nobody sees. This module surfaces those.

Design choices mirror the taxonomy notifier -- see that module for
the full rationale on issue reuse, closed-issue semantics, and
failure isolation. Delta:

- **Threshold, not "any failure".** We tolerate a small share of
  known-bad upstream files (broken YAML that lives on in the repo,
  format-mismatch edge cases) via `_SUCCESS_THRESHOLD_PCT`. A single
  failure in a 5000-rule corpus shouldn't page anyone.

- **Absolute floor.** Small corpora (<50 discovered) skip the
  threshold check -- a single failure in a 10-rule source would
  register as a 10% drop and spam the queue.
"""

import logging
from typing import Optional

import httpx

from app.config import settings
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_ISSUE_TITLE_PREFIX = "[parse-failure]"

# A source with success rate below this alerts. 99.5% tolerates ~1 in
# 200 upstream files being unparseable -- past that, something has
# genuinely regressed.
_SUCCESS_THRESHOLD_PCT = 99.5

# Skip the threshold check for very small corpora. A single failure
# in a 10-rule source is a 10% drop that would otherwise page every
# night; if the corpus is that small, humans can notice via the sync
# summary without a dedicated issue.
_SMALL_CORPUS_FLOOR = 50


async def notify_parse_failures(repo_results: dict, sync_job_id: str) -> None:
    """Emit parse-failure signals for sources that dropped below threshold.

    Args:
        repo_results: The `sync_job.repository_results` dict. Each value
            is expected to have `rules_discovered`, `parse_failure_count`,
            and `parse_failure_samples` keys (populated by scheduler
            from `IngestionStats.errors`).
        sync_job_id: The sync job's UUID -- included in the issue body
            so an engineer can cross-reference against logs.

    Returns None. Never raises -- failures are logged and swallowed
    since this is informational and must not degrade sync status.
    """
    if not settings.taxonomy_notifications_enabled:
        logger.debug("Notifications disabled -- skipping parse-failure notify")
        return

    if not settings.github_token:
        logger.info(
            "Parse-failure notifier enabled but no GITHUB_TOKEN "
            "configured -- skipping"
        )
        return

    if not settings.github_repo_owner or not settings.github_repo_name:
        logger.warning(
            "Parse-failure notifier enabled but "
            "GITHUB_REPO_OWNER/NAME missing -- skipping"
        )
        return

    problem_repos = []
    for name, result in repo_results.items():
        if not isinstance(result, dict):
            continue
        if not result.get("sync_success"):
            continue
        discovered = result.get("rules_discovered", 0)
        failures = result.get("parse_failure_count", 0)
        if discovered <= 0 or failures <= 0:
            continue
        if discovered < _SMALL_CORPUS_FLOOR:
            # Small corpus -- a single failure would be a huge percent
            # swing. Skip the threshold, but log so we don't lose it.
            logger.info(
                f"{name}: {failures} parse failure(s) in a small corpus "
                f"({discovered} discovered); below alerting floor"
            )
            continue
        success_rate = 100.0 * (discovered - failures) / discovered
        if success_rate < _SUCCESS_THRESHOLD_PCT:
            problem_repos.append((name, result, failures, success_rate))

    if not problem_repos:
        logger.info("No parse-failure regressions past threshold")
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
        for name, result, failures, success_rate in problem_repos:
            try:
                await _notify_repo_parse_failures(
                    client, name, result, sync_job_id, failures, success_rate
                )
            except Exception as e:
                # Per-repo isolation -- one broken call must not block
                # notifications for the other affected sources.
                logger.warning(
                    f"Failed to notify parse failures for {name}: "
                    f"{type(e).__name__}: {e}"
                )


async def _notify_repo_parse_failures(
    client: httpx.AsyncClient,
    repo_name: str,
    result: dict,
    sync_job_id: str,
    failure_count: int,
    success_rate: float,
) -> None:
    """Open or update the parse-failure issue for a single source."""
    owner = settings.github_repo_owner
    repo = settings.github_repo_name
    title = f"{_ISSUE_TITLE_PREFIX} {repo_name}"
    body = _format_parse_failure_body(
        repo_name, result, sync_job_id, failure_count, success_rate
    )

    existing = await _find_open_issue(client, owner, repo, title)
    if existing is not None:
        await _post_comment(client, owner, repo, existing, body)
        logger.info(
            f"Posted parse-failure comment on #{existing} for {repo_name} "
            f"({failure_count} failures, {success_rate:.2f}% success)"
        )
        return

    number = await _create_issue(client, owner, repo, title, body)
    logger.info(
        f"Opened parse-failure issue #{number} for {repo_name} "
        f"({failure_count} failures, {success_rate:.2f}% success)"
    )


async def _find_open_issue(
    client: httpx.AsyncClient, owner: str, repo: str, title: str
) -> Optional[int]:
    """Return the issue number of an open issue with this exact title, or None."""
    query = f'repo:{owner}/{repo} is:issue is:open "{title}" in:title'
    response = await client.get(
        "/search/issues", params={"q": query, "per_page": 20}
    )
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
        json={
            "title": title,
            "body": body,
            "labels": ["parse-failure", "drift"],
        },
    )
    response.raise_for_status()
    return response.json()["number"]


async def _post_comment(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    issue_number: int,
    body: str,
) -> None:
    """Post a comment on an existing issue."""
    response = await client.post(
        f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        json={"body": body},
    )
    response.raise_for_status()


def _format_parse_failure_body(
    repo_name: str,
    result: dict,
    sync_job_id: str,
    failure_count: int,
    success_rate: float,
) -> str:
    """Build the markdown body for a parse-failure issue or comment."""
    discovered = result.get("rules_discovered", 0)
    stored = result.get("rules_stored", 0)
    samples = result.get("parse_failure_samples") or []

    # Group samples by stage so PARSE and NORMALIZE regressions are
    # easy to eyeball separately.
    by_stage: dict[str, list[dict]] = {}
    for s in samples:
        stage = s.get("stage", "unknown")
        by_stage.setdefault(stage, []).append(s)

    lines = [
        f"**Sync job:** `{sync_job_id}`",
        f"**Timestamp (UTC):** {utcnow().isoformat()}",
        f"**Source:** `{repo_name}`",
        "",
        f"- Rules discovered: **{discovered}**",
        f"- Rules stored: **{stored}**",
        f"- Parse/normalize failures: **{failure_count}**",
        f"- Ingest success rate: **{success_rate:.2f}%** "
        f"(threshold {_SUCCESS_THRESHOLD_PCT:.1f}%)",
        "",
        "## What to check",
        "",
        f"1. Did upstream (`{repo_name}`) change its rule schema?",
        f"2. Did our parser or normalizer regress? "
        f"See `backend/app/parsers/{repo_name}.py` + "
        f"`backend/app/normalizers/{repo_name}.py`.",
        "3. If failures are legitimate upstream breakage, document the "
        "affected files and consider adding them to a skip-list.",
        "",
        "## Failing files (sample)",
        "",
    ]

    for stage in ("parse", "normalize"):
        stage_samples = by_stage.get(stage, [])
        if not stage_samples:
            continue
        lines.append(f"### {stage.upper()} stage ({len(stage_samples)} shown)")
        lines.append("")
        lines.append("| Severity | File | Message |")
        lines.append("| :--- | :--- | :--- |")
        for s in stage_samples[:20]:
            severity = s.get("severity", "?")
            file_path = str(s.get("file_path", "?")).replace("|", "\\|")
            message = str(s.get("message", "")).replace("|", "\\|")[:180]
            lines.append(f"| {severity} | `{file_path}` | {message} |")
        lines.append("")

    other = {k: v for k, v in by_stage.items() if k not in ("parse", "normalize")}
    if other:
        lines.append(f"### Other stages: {', '.join(sorted(other))}")
        lines.append("")

    return "\n".join(lines)
