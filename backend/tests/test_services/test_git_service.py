"""Tests for the GitService — git log-based rule date fallback."""

import os
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from app.services.git_service import GitService


def _git(cwd: Path, *args: str, env_overrides: dict | None = None) -> None:
    """Run a git command in `cwd` with committer/author identity pinned.

    We set identity env vars here instead of relying on the test runner's
    global git config, so these tests don't depend on whether the CI or
    dev machine has a user.name / user.email configured.
    """
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Test Author"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "Test Author"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    if env_overrides:
        env.update(env_overrides)
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
    )


def _commit_file(
    repo: Path,
    relative_path: str,
    content: str,
    iso_date: str,
    message: str,
) -> None:
    """Write `content` to a file at `relative_path` and commit it at a fixed date."""
    full_path = repo / relative_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content)
    _git(repo, "add", relative_path)
    _git(
        repo,
        "commit",
        "-m",
        message,
        env_overrides={"GIT_AUTHOR_DATE": iso_date, "GIT_COMMITTER_DATE": iso_date},
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A temp git repo with a single file that has two commits on different days."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")

    _commit_file(
        repo,
        "rules/example.yml",
        "title: Example v1\n",
        iso_date="2024-03-15T10:00:00+00:00",
        message="Add example rule",
    )
    _commit_file(
        repo,
        "rules/example.yml",
        "title: Example v2 updated\n",
        iso_date="2024-06-20T14:30:00+00:00",
        message="Update example rule",
    )
    return repo


def test_get_file_dates_returns_add_and_latest_commit(git_repo: Path) -> None:
    """Happy path: created = first add commit, modified = most recent commit."""
    svc = GitService(git_repo)
    created, modified = svc.get_file_dates("rules/example.yml")

    assert created == datetime(2024, 3, 15, 10, 0, 0)
    assert modified == datetime(2024, 6, 20, 14, 30, 0)


def test_follows_renames_across_directories(git_repo: Path) -> None:
    """If a file is renamed, --follow should still report the original add date."""
    # Rename the file into a nested subdirectory
    (git_repo / "rules" / "moved").mkdir()
    subprocess.run(
        ["git", "mv", "rules/example.yml", "rules/moved/example.yml"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    _git(
        git_repo,
        "commit",
        "-m",
        "Move example rule",
        env_overrides={
            "GIT_AUTHOR_DATE": "2024-09-01T09:00:00+00:00",
            "GIT_COMMITTER_DATE": "2024-09-01T09:00:00+00:00",
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
    )

    svc = GitService(git_repo)
    created, modified = svc.get_file_dates("rules/moved/example.yml")

    # Original add date should still come through the rename chain
    assert created == datetime(2024, 3, 15, 10, 0, 0)
    # Latest modification is now the rename commit
    assert modified == datetime(2024, 9, 1, 9, 0, 0)


def test_missing_file_returns_none(git_repo: Path) -> None:
    """A path that isn't tracked in git should return (None, None), not raise."""
    svc = GitService(git_repo)
    created, modified = svc.get_file_dates("rules/does_not_exist.yml")

    assert created is None
    assert modified is None


def test_missing_repo_path_returns_none(tmp_path: Path) -> None:
    """A repo_path that doesn't exist at all should return None gracefully."""
    svc = GitService(tmp_path / "nonexistent")
    created, modified = svc.get_file_dates("any/path.yml")

    assert created is None
    assert modified is None


def test_non_git_directory_returns_none(tmp_path: Path) -> None:
    """A real directory that isn't a git repo should return None gracefully."""
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    (plain_dir / "file.txt").write_text("hello")

    svc = GitService(plain_dir)
    created, modified = svc.get_file_dates("file.txt")

    assert created is None
    assert modified is None


def test_shallow_clone_returns_none(git_repo: Path, tmp_path: Path) -> None:
    """A shallow (depth=1) clone must return None rather than the tip commit.

    On a depth=1 clone every file would get the same tip-of-master commit
    date — that's worse than None because it looks like real data. Detect
    the shallow state via `git rev-parse --is-shallow-repository` and skip.
    """
    shallow_path = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth=1", f"file://{git_repo}", str(shallow_path)],
        check=True,
        capture_output=True,
    )

    svc = GitService(shallow_path)
    created, modified = svc.get_file_dates("rules/example.yml")

    assert created is None
    assert modified is None


def test_parse_iso_datetime_strips_timezone() -> None:
    """Git %aI output is tz-aware; we return naive UTC to match Detection schema."""
    result = GitService._parse_iso_datetime("2024-03-15T14:22:01+00:00")
    assert result == datetime(2024, 3, 15, 14, 22, 1)
    assert result.tzinfo is None


def test_parse_iso_datetime_handles_non_utc_offset() -> None:
    """Non-UTC offsets should be converted to UTC before dropping tzinfo."""
    # 2024-03-15 09:00:00 -05:00 == 2024-03-15 14:00:00 UTC
    result = GitService._parse_iso_datetime("2024-03-15T09:00:00-05:00")
    assert result == datetime(2024, 3, 15, 14, 0, 0)


def test_parse_iso_datetime_returns_none_on_garbage() -> None:
    """Malformed input should return None, not raise."""
    assert GitService._parse_iso_datetime("") is None
    assert GitService._parse_iso_datetime("not-a-date") is None
