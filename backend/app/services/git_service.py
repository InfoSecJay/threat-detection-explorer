"""Git metadata lookup service.

Provides git log-based fallback for detection rules that don't embed creation
or modification dates in their source format (e.g., Microsoft Sentinel YAML,
Elastic Hunting/Protections TOML, Sublime YAML).

Uses subprocess to shell out to the system git binary — avoids GitPython
overhead for simple log queries and works with whatever git is already
available in the environment.

Gracefully handles shallow clones: if git history doesn't go back far enough
to find a file's creation commit, `get_created_date` returns None rather
than raising, so downstream normalizers can decide how to handle missing data.
"""

import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class GitService:
    """Query git commit metadata for files inside a locally-cloned repository.

    One instance per repo. Safe to construct eagerly even if the repo path
    doesn't exist yet — methods return None on any failure (missing path,
    missing file, git not installed, shallow history, etc.) so callers can
    treat it as a best-effort data source.
    """

    def __init__(self, repo_path: Path):
        """Initialize with the root path of a locally-cloned git repository."""
        self.repo_path = Path(repo_path)
        # Cache the shallow check once per instance. We only care whether
        # the clone has enough history to tell file-created from file-modified;
        # if it's a depth=1 shallow, every file's "created" and "modified" would
        # collapse to the same tip-of-master commit date, which is misleading.
        # Partial clones (--filter=blob:none) are NOT shallow — this check lets
        # them through correctly.
        self._is_shallow: Optional[bool] = None  # lazily resolved

    def get_file_dates(
        self, relative_path: str
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """Return (created_date, modified_date) for a file from git history.

        created_date: timestamp of the commit that first added this file
          (follows renames via `git log --follow`). Returns None if the file
          has no add-diff in the available history (shallow clone, file not
          tracked, etc.).

        modified_date: timestamp of the most recent commit that touched this
          file. Returns None if the file isn't tracked or git fails.

        Both values are author-date timestamps in ISO 8601 (%aI), parsed as
        timezone-aware datetimes then converted to naive UTC to match the
        rest of the codebase's datetime handling.
        """
        return (
            self.get_created_date(relative_path),
            self.get_modified_date(relative_path),
        )

    def get_created_date(self, relative_path: str) -> Optional[datetime]:
        """Return the commit date when this file was first added to the repo.

        Uses `git log --follow` to walk the file's full history (following
        across renames), then takes the LAST line — which is the oldest
        commit and, by definition, the commit that introduced the file.

        Notes on why this command shape:
          - We avoid `--diff-filter=A` because `--follow` has known quirks
            with diff filters and sometimes returns empty for renamed files.
          - We avoid `--reverse` because `git log --follow --reverse` is a
            known broken combination: `--reverse` truncates the follow chain
            at the rename boundary and drops the pre-rename commits entirely.
            Instead we use default (newest-first) order and take the last line.

        Returns None if:
          - The repo path doesn't exist or isn't a git repo
          - The file isn't tracked in the current history
          - History is too shallow to reach the original add commit
          - git is not installed or the subprocess fails
        """
        # --follow: follow renames (required for files that have been moved)
        # --format=%aI: author date in strict ISO 8601 (timezone-aware)
        output = self._run_git_log(
            [
                "log",
                "--follow",
                "--format=%aI",
                "--",
                self._normalize_path(relative_path),
            ]
        )
        if not output:
            return None

        # Output is newest-first; the oldest commit through the follow chain
        # is the last non-empty line — this is the original add commit.
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return None
        return self._parse_iso_datetime(lines[-1])

    def get_modified_date(self, relative_path: str) -> Optional[datetime]:
        """Return the commit date of the most recent change to this file.

        Uses `git log -1 --follow` to get the latest commit that touched the
        file, following across renames.

        Returns None on any failure (see get_created_date for details).
        """
        # -1: limit to most recent
        # --follow: follow renames
        # --format=%aI: author date ISO 8601
        output = self._run_git_log(
            [
                "log",
                "-1",
                "--follow",
                "--format=%aI",
                "--",
                self._normalize_path(relative_path),
            ]
        )
        if not output:
            return None

        return self._parse_iso_datetime(output.strip())

    def get_file_history(self, relative_path: str, limit: int = 10) -> list[dict]:
        """Return the last `limit` commits that touched a file, newest first.

        Each entry is {"sha", "author", "date", "subject"} with `date` as an
        ISO 8601 string (author date, timezone-aware as git printed it).
        Follows renames like the date lookups. Best-effort: [] on shallow
        clones, untracked files, or any git failure. Feeds the rule
        history timeline (#127); the cap keeps the JSON column small.
        """
        output = self._run_git_log(
            [
                "log",
                "--follow",
                f"-n{int(limit)}",
                "--format=%H%x1f%an%x1f%aI%x1f%s",
                "--",
                self._normalize_path(relative_path),
            ]
        )
        return self._parse_history(output)

    @staticmethod
    def _parse_history(output: Optional[str]) -> list[dict]:
        touches: list[dict] = []
        for line in (output or "").splitlines():
            parts = line.strip().split("")
            if len(parts) < 3 or not parts[0]:
                continue
            sha, author, date = parts[0].strip(), parts[1].strip(), parts[2].strip()
            subject = parts[3].strip() if len(parts) > 3 else ""
            touches.append({"sha": sha, "author": author, "date": date, "subject": subject[:200]})
        return touches

    @staticmethod
    def _normalize_path(relative_path: str) -> str:
        """Normalize path separators to forward slashes for git.

        On Windows our parsers produce paths via `str(Path(...))` which uses
        backslashes. Git-for-Windows happens to accept backslashes, but git's
        documented pathspec format is forward-slash and Linux git (Railway)
        will not accept backslashes at all. Normalize eagerly so we work the
        same everywhere.
        """
        return relative_path.replace("\\", "/")

    def _check_shallow(self) -> bool:
        """Return True if this is a shallow clone with no real history.

        Uses `git rev-parse --is-shallow-repository` (git 2.15+). On a shallow
        clone, returning dates would give every file the same clone-time
        commit date, which is worse than returning None.

        Cached per instance.
        """
        if self._is_shallow is not None:
            return self._is_shallow

        if not self.repo_path.exists():
            self._is_shallow = True
            return True

        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            # On any error, assume shallow/unavailable so we return None rather
            # than risking garbage dates.
            self._is_shallow = True
            return True

        if result.returncode != 0:
            self._is_shallow = True
            return True

        self._is_shallow = result.stdout.strip().lower() == "true"
        return self._is_shallow

    def _run_git_log(self, args: list[str]) -> Optional[str]:
        """Run `git <args>` in the repo directory and return stdout.

        Returns None on any failure — git not installed, repo missing,
        non-zero exit, timeout, or shallow clone. Logs at debug for
        expected failures because callers treat this as best-effort.
        """
        if not self.repo_path.exists():
            return None

        if self._check_shallow():
            return None

        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except FileNotFoundError:
            logger.warning("git binary not found on PATH; date fallback disabled")
            return None
        except subprocess.TimeoutExpired:
            logger.debug(f"git log timed out for args {args[:3]}...")
            return None
        except Exception as e:
            logger.debug(f"git log failed unexpectedly: {e}")
            return None

        if result.returncode != 0:
            # Common non-fatal cases: file not tracked, bad path, shallow history
            # Log at debug level to avoid flooding logs during full ingestion
            logger.debug(
                f"git log non-zero exit ({result.returncode}) for {args[-1]}: "
                f"{result.stderr.strip()[:200]}"
            )
            return None

        return result.stdout or None

    @staticmethod
    def _parse_iso_datetime(value: str) -> Optional[datetime]:
        """Parse a strict ISO 8601 timestamp from git (%aI) to naive UTC.

        Git's %aI format produces values like "2024-03-15T14:22:01+00:00".
        We parse as timezone-aware, convert to UTC, then drop the tzinfo to
        match the rest of the codebase (Detection.rule_created_date is a
        naive DateTime column).
        """
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is not None:
            # Convert to UTC then strip tzinfo for naive comparison
            from datetime import timezone

            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
