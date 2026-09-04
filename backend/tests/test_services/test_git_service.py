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


def _move_example(git_repo: Path) -> None:
    (git_repo / "rules" / "moved").mkdir()
    subprocess.run(
        ["git", "mv", "rules/example.yml", "rules/moved/example.yml"],
        cwd=git_repo, check=True, capture_output=True,
    )
    _git(
        git_repo, "commit", "-m", "Move example rule",
        env_overrides={"GIT_AUTHOR_DATE": "2024-09-01T09:00:00+00:00", "GIT_COMMITTER_DATE": "2024-09-01T09:00:00+00:00"},
    )


def test_index_answers_like_the_per_file_lookups_and_follows_renames(git_repo: Path) -> None:
    """One walk (#132) must give the same dates and history as three
    `git log --follow` calls per file, rename chain included."""
    _move_example(git_repo)
    _commit_file(git_repo, "rules/other.yml", "title: Other\n", "2024-10-05T08:00:00+00:00", "Add other rule")

    per_file = GitService(git_repo)
    indexed = GitService(git_repo)
    assert indexed.build_index() == 2  # moved/example.yml (its old path folded in) + other.yml
    for path in ("rules/moved/example.yml", "rules/other.yml", "rules/does_not_exist.yml"):
        assert indexed.get_file_dates(path) == per_file.get_file_dates(path), path
        assert indexed.get_file_history(path) == per_file.get_file_history(path), path

    assert indexed.get_file_dates("rules/moved/example.yml") == (datetime(2024, 3, 15, 10, 0, 0), datetime(2024, 9, 1, 9, 0, 0))
    assert [h["subject"] for h in indexed.get_file_history("rules/moved/example.yml")] == [
        "Move example rule", "Update example rule", "Add example rule",
    ]
    assert indexed.get_file_history("rules/moved/example.yml", limit=1)[0]["author"] == "Test Author"
    # Backslash paths (Windows parsers) hit the same index entry.
    assert indexed.get_file_dates("rules\\moved\\example.yml")[0] == datetime(2024, 3, 15, 10, 0, 0)


def test_index_on_shallow_clone_uses_only_commits_inside_the_window(git_repo: Path, tmp_path: Path) -> None:
    """depth=2 of a 3-commit history: the boundary commit (which git shows
    as adding the whole tree) contributes nothing; the one real commit
    inside the window gives modified + history, and created stays None
    because the birth is out of reach."""
    _move_example(git_repo)
    shallow_path = tmp_path / "shallow2"
    subprocess.run(
        ["git", "clone", "--depth=2", f"file://{git_repo}", str(shallow_path)],
        check=True, capture_output=True,
    )
    svc = GitService(shallow_path)
    assert svc.build_index() >= 1
    created, modified = svc.get_file_dates("rules/moved/example.yml")
    assert created is None
    assert modified == datetime(2024, 9, 1, 9, 0, 0)
    assert [h["subject"] for h in svc.get_file_history("rules/moved/example.yml")] == ["Move example rule"]

    # depth=1: the only commit is the boundary -> nothing, like before.
    one = tmp_path / "shallow1"
    subprocess.run(["git", "clone", "--depth=1", f"file://{git_repo}", str(one)], check=True, capture_output=True)
    svc1 = GitService(one)
    svc1.build_index()
    assert svc1.get_file_dates("rules/moved/example.yml") == (None, None)
    assert svc1.get_file_history("rules/moved/example.yml") == []


def test_index_failure_falls_back_to_per_file(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    svc = GitService(plain)
    assert svc.build_index() == 0
    assert svc._index is None
    assert svc.get_file_dates("x.yml") == (None, None)


def test_parse_walk_handles_quoted_paths_and_copies() -> None:
    out = (
        "\x1eaaa\x1fAda\x1f2024-05-01T00:00:00+00:00\x1fRename it\n\n"
        "R090\trules/old name.yml\t\"rules/new \\303\\251.yml\"\n"
        "\x1ebbb\x1fBob\x1f2024-04-01T00:00:00+00:00\x1fAdd it\n\n"
        "A\trules/old name.yml\n"
        "C075\trules/old name.yml\trules/copy.yml\n"
    )
    index = GitService._parse_walk(out, boundary=set())
    assert [t[0] for t in index["rules/new é.yml"]] == ["aaa", "bbb"]
    assert index["rules/new é.yml"][-1][4] == "A"
    assert index["rules/copy.yml"][0][4] == "C"
    assert GitService._parse_walk(out, boundary={"bbb"})["rules/new é.yml"] == [("aaa", "Ada", "2024-05-01T00:00:00+00:00", "Rename it", "R")]


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
