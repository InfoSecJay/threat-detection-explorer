"""Upstream tree verification — sanity-check what we ingested vs GitHub truth.

After each nightly sync, fetch the upstream tree via the GitHub API,
apply our own discovery patterns to it, and cross-check the expected
file count against ``stats.discovered``. Alerts on mismatch (glob
drift, sparse-checkout drift, branch drift) via the same GitHub-issue
notifier plumbing as taxonomy drift.

Also snapshots per-top-level-directory file counts to
``sync_job.repository_results[<repo>]["upstream_directory_counts"]``
and diffs vs the previous successful sync job — flags NEW or VANISHED
top-level directories caught by our globs. Catches the class of bug
where an upstream ``rules-*/`` autoglob silently absorbs a new
directory (mysterious count jump with no code change).

Design mirrors ``taxonomy_notifier.py``:
- Feature-flagged via ``settings.taxonomy_notifications_enabled``.
- Never blocks the sync — errors log a warning + return.
- Failures per repo are isolated.
- Reuses the same GitHub PAT and repo config for the alerting side.
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.services.rule_discovery import RuleDiscoveryService
from app.services.repository_sync import (
    RepositorySyncService,
    SPARSE_CHECKOUT_BRANCHES,
)
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_ISSUE_TITLE_PREFIX = "[upstream-drift]"

# How much of a discovery/expected mismatch is tolerable before we alert.
# Some jitter is fine: upstream files may add/vanish between the clone
# and the tree fetch, and our sparse-clone can be a few files off from
# a full clone in rare edge cases. 5% catches the "we're missing a
# whole directory" class without noise.
_MISMATCH_THRESHOLD_PCT = 5.0


# ── Glob -> regex ────────────────────────────────────────────────────


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a git-style glob (with ``**`` support) to a full-path regex.

    Semantics match the discovery patterns already used by
    ``RuleDiscoveryService`` when it globs the local clone:
      - ``**/``  = zero or more path segments including the trailing /
      - ``**``   = zero or more of anything (any characters)
      - ``*``    = zero or more non-slash characters
      - ``?``    = one non-slash character
    Regex specials in the literal parts are escaped.
    """
    p = pattern.replace("\\", "/")
    out: list[str] = []
    i = 0
    while i < len(p):
        if p[i:i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif p[i:i + 2] == "**":
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append("[^/]*")
            i += 1
        elif p[i] == "?":
            out.append("[^/]")
            i += 1
        elif p[i] in r".^$+(){}[]|\\":
            out.append("\\" + p[i])
            i += 1
        else:
            out.append(p[i])
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _apply_patterns(
    files: list[str],
    include_patterns: list[str],
    exclude_dirs: set[str],
) -> list[str]:
    """Return the subset of `files` that our discovery patterns would match."""
    lowered_excludes = {d.lower() for d in exclude_dirs}
    regexes = [_glob_to_regex(p) for p in include_patterns]
    matches: list[str] = []
    for f in files:
        segments = f.split("/")
        if any(seg.lower() in lowered_excludes for seg in segments):
            continue
        if any(r.match(f) for r in regexes):
            matches.append(f)
    return matches


# ── GitHub tree fetch ────────────────────────────────────────────────


def _owner_repo_from_url(url: str) -> Optional[tuple[str, str]]:
    """Parse `https://github.com/OWNER/REPO(.git)?` -> (OWNER, REPO)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.netloc != "github.com":
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


async def _fetch_upstream_files(
    client: httpx.AsyncClient, owner: str, repo: str, branch: str,
) -> list[str]:
    """Fetch every file path in a GitHub repo's tree, recursively.

    Two calls: first resolves the branch's head commit to get the tree
    SHA; second fetches the tree with `recursive=1`. Returns a flat
    list of blob paths (directories filtered out).
    """
    br = await client.get(f"/repos/{owner}/{repo}/branches/{branch}")
    br.raise_for_status()
    tree_sha = br.json()["commit"]["commit"]["tree"]["sha"]

    tr = await client.get(
        f"/repos/{owner}/{repo}/git/trees/{tree_sha}",
        params={"recursive": "1"},
    )
    tr.raise_for_status()
    data = tr.json()
    return [
        entry["path"]
        for entry in data.get("tree", [])
        if entry.get("type") == "blob"
    ]


# ── Directory-count snapshot + diff ──────────────────────────────────


def _directory_counts(files: list[str]) -> dict[str, int]:
    """Group `files` by their TOP-level directory, count each.

    Files at the repo root (no slash in the path) roll up under `"."`.
    """
    counts: dict[str, int] = {}
    for f in files:
        top = f.split("/", 1)[0] if "/" in f else "."
        counts[top] = counts.get(top, 0) + 1
    return counts


def _diff_directory_counts(
    current: dict[str, int], previous: Optional[dict[str, int]],
) -> dict[str, dict]:
    """Compare current + previous per-directory counts.

    Returns a dict keyed by directory name with entries indicating
    whether it's `new`, `vanished`, or a `count_changed` and by how
    much. Only meaningful when there IS a previous baseline; returns
    {} otherwise.
    """
    if not previous:
        return {}
    diffs: dict[str, dict] = {}
    all_dirs = set(current) | set(previous)
    for d in all_dirs:
        cur = current.get(d, 0)
        prev = previous.get(d, 0)
        if cur > 0 and prev == 0:
            diffs[d] = {"kind": "new", "count": cur}
        elif cur == 0 and prev > 0:
            diffs[d] = {"kind": "vanished", "previous_count": prev}
        elif cur != prev and prev > 0:
            change_pct = (cur - prev) / prev * 100.0
            if abs(change_pct) >= 20:
                diffs[d] = {
                    "kind": "count_changed",
                    "previous_count": prev,
                    "count": cur,
                    "change_pct": round(change_pct, 1),
                }
    return diffs


# ── Public entry point ───────────────────────────────────────────────


async def verify_upstream(
    repo_results: dict,
    sync_job_id: str,
    previous_repo_results: Optional[dict] = None,
) -> None:
    """Cross-check every synced repo against its upstream GitHub tree.

    Mutates `repo_results[<name>]` in place to add:
      - `upstream_expected_count`: what our patterns would match on
        the upstream tree
      - `upstream_actual_count`: what we actually discovered
      - `upstream_directory_counts`: per-top-level-directory counts
        on the upstream tree
      - `upstream_directory_diffs`: diff vs previous run
      - `upstream_verification_status`: one of {ok, mismatch, skipped,
        error, unreachable}

    Alerts (GitHub issue open/comment) fired for `mismatch` and for
    any non-empty `upstream_directory_diffs`.
    """
    if not settings.taxonomy_notifications_enabled:
        logger.debug("Upstream verification disabled — skipping")
        return

    prev = previous_repo_results or {}

    async with httpx.AsyncClient(
        base_url=_GITHUB_API,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **(
                {"Authorization": f"Bearer {settings.github_token}"}
                if settings.github_token else {}
            ),
        },
        timeout=30.0,
    ) as client:
        for repo_name, result in list(repo_results.items()):
            if not isinstance(result, dict):
                continue
            if not result.get("sync_success"):
                # Nothing to verify if the clone itself failed.
                result["upstream_verification_status"] = "skipped"
                continue

            prev_dirs = None
            if repo_name in prev and isinstance(prev[repo_name], dict):
                prev_dirs = prev[repo_name].get("upstream_directory_counts")

            try:
                await _verify_one_repo(
                    client, repo_name, result, sync_job_id, prev_dirs,
                )
            except Exception as e:
                logger.warning(
                    f"Upstream verification failed for {repo_name}: "
                    f"{type(e).__name__}: {e}"
                )
                result["upstream_verification_status"] = "error"
                result["upstream_verification_error"] = f"{type(e).__name__}: {e}"


async def _verify_one_repo(
    client: httpx.AsyncClient,
    repo_name: str,
    result: dict,
    sync_job_id: str,
    prev_directory_counts: Optional[dict[str, int]],
) -> None:
    config = RepositorySyncService.REPO_CONFIGS.get(repo_name)
    if not config:
        result["upstream_verification_status"] = "skipped"
        return

    owner_repo = _owner_repo_from_url(config["url"])
    if not owner_repo:
        result["upstream_verification_status"] = "skipped"
        return
    owner, repo = owner_repo

    branch = SPARSE_CHECKOUT_BRANCHES.get(repo_name, "master")

    upstream_files = await _fetch_upstream_files(client, owner, repo, branch)

    patterns = RuleDiscoveryService.DISCOVERY_PATTERNS.get(repo_name)
    if not patterns:
        result["upstream_verification_status"] = "skipped"
        return

    expected_files = _apply_patterns(
        upstream_files,
        patterns.get("include_patterns", []),
        set(patterns.get("exclude_dirs", [])),
    )
    expected_count = len(expected_files)
    actual_count = int(result.get("rules_discovered") or 0)

    # Directory-count snapshot (based on EXPECTED files, not the full
    # upstream tree — the latter is dominated by docs/tests/etc. we
    # don't care about).
    directory_counts = _directory_counts(expected_files)
    directory_diffs = _diff_directory_counts(directory_counts, prev_directory_counts)

    result["upstream_expected_count"] = expected_count
    result["upstream_actual_count"] = actual_count
    result["upstream_directory_counts"] = directory_counts
    result["upstream_directory_diffs"] = directory_diffs

    # Threshold: absolute-count mismatch beyond 5% of expected OR
    # any non-empty per-directory diff.
    mismatch_pct = 0.0
    if expected_count > 0:
        mismatch_pct = abs(actual_count - expected_count) / expected_count * 100.0
    has_dir_drift = bool(directory_diffs)

    if mismatch_pct > _MISMATCH_THRESHOLD_PCT or has_dir_drift:
        result["upstream_verification_status"] = "mismatch"
        # Alert (best-effort — errors don't break the sync).
        if settings.github_token and settings.github_repo_owner and settings.github_repo_name:
            try:
                await _notify_upstream_mismatch(
                    client,
                    repo_name=repo_name,
                    expected=expected_count,
                    actual=actual_count,
                    mismatch_pct=mismatch_pct,
                    directory_counts=directory_counts,
                    directory_diffs=directory_diffs,
                    sync_job_id=sync_job_id,
                )
            except Exception as e:
                logger.warning(
                    f"Upstream drift notification failed for {repo_name}: "
                    f"{type(e).__name__}: {e}"
                )
    else:
        result["upstream_verification_status"] = "ok"


# ── Notifier ─────────────────────────────────────────────────────────


async def _notify_upstream_mismatch(
    client: httpx.AsyncClient,
    *,
    repo_name: str,
    expected: int,
    actual: int,
    mismatch_pct: float,
    directory_counts: dict[str, int],
    directory_diffs: dict[str, dict],
    sync_job_id: str,
) -> None:
    """Open or update the `[upstream-drift] <repo>` issue."""
    owner = settings.github_repo_owner
    repo = settings.github_repo_name
    title = f"{_ISSUE_TITLE_PREFIX} {repo_name}"
    body = _format_mismatch_body(
        repo_name=repo_name,
        expected=expected,
        actual=actual,
        mismatch_pct=mismatch_pct,
        directory_counts=directory_counts,
        directory_diffs=directory_diffs,
        sync_job_id=sync_job_id,
    )

    existing = await _find_open_issue(client, owner, repo, title)
    if existing is not None:
        await _post_comment(client, owner, repo, existing, body)
        logger.info(
            f"Posted upstream drift comment on #{existing} for {repo_name} "
            f"(expected={expected} actual={actual})"
        )
        return

    number = await _create_issue(client, owner, repo, title, body)
    logger.info(
        f"Opened upstream drift issue #{number} for {repo_name} "
        f"(expected={expected} actual={actual})"
    )


async def _find_open_issue(
    client: httpx.AsyncClient, owner: str, repo: str, title: str,
) -> Optional[int]:
    query = f'repo:{owner}/{repo} is:issue is:open "{title}" in:title'
    response = await client.get("/search/issues", params={"q": query, "per_page": 20})
    response.raise_for_status()
    for item in response.json().get("items", []):
        if item.get("title", "").strip() == title:
            return item.get("number")
    return None


async def _create_issue(
    client: httpx.AsyncClient, owner: str, repo: str, title: str, body: str,
) -> int:
    response = await client.post(
        f"/repos/{owner}/{repo}/issues",
        json={"title": title, "body": body, "labels": ["upstream-drift", "drift"]},
    )
    response.raise_for_status()
    return response.json()["number"]


async def _post_comment(
    client: httpx.AsyncClient, owner: str, repo: str, issue_number: int, body: str,
) -> None:
    response = await client.post(
        f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        json={"body": body},
    )
    response.raise_for_status()


def _format_mismatch_body(
    *,
    repo_name: str,
    expected: int,
    actual: int,
    mismatch_pct: float,
    directory_counts: dict[str, int],
    directory_diffs: dict[str, dict],
    sync_job_id: str,
) -> str:
    lines = [
        f"**Sync job:** `{sync_job_id}`",
        f"**Timestamp (UTC):** {utcnow().isoformat()}",
        f"**Repo:** `{repo_name}`",
        "",
        f"- Upstream tree matched our discovery patterns: **{expected}** files",
        f"- We actually discovered: **{actual}**",
        f"- Mismatch: **{mismatch_pct:.1f}%**",
        "",
    ]

    if directory_diffs:
        lines.extend([
            "## Directory-scope drift vs previous sync",
            "",
            "| Directory | Change |",
            "| :--- | :--- |",
        ])
        for d, info in sorted(directory_diffs.items()):
            if info["kind"] == "new":
                change = f"NEW ({info['count']} files) — our globs started matching this directory"
            elif info["kind"] == "vanished":
                change = f"VANISHED (previously {info['previous_count']} files) — our globs stopped matching this directory"
            else:
                change = (
                    f"{info['previous_count']} -> {info['count']} "
                    f"({info['change_pct']:+.1f}%)"
                )
            lines.append(f"| `{d}` | {change} |")
        lines.append("")

    lines.extend([
        "## Current directory breakdown (upstream files matched by our globs)",
        "",
        "| Directory | Count |",
        "| :--- | ---: |",
    ])
    for d in sorted(directory_counts, key=lambda k: -directory_counts[k]):
        lines.append(f"| `{d}` | {directory_counts[d]} |")

    lines.extend([
        "",
        "## Investigate",
        "",
        f"- `backend/app/services/rule_discovery.py::DISCOVERY_PATTERNS['{repo_name}']`",
        f"- `backend/app/services/repository_sync.py::SPARSE_CHECKOUT_PATTERNS.get('{repo_name}')` (if sparse-cloned)",
        "- Compare the upstream tree at "
        f"`https://github.com/<owner>/<repo>/tree/<branch>` against the count above.",
    ])

    return "\n".join(lines)
