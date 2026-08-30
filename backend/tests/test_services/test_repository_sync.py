"""RepositorySyncService: full clone, sparse clone on a non-master
branch, re-clone of an existing checkout, git failure, unknown repo
(#24). Remotes are local git repositories -- no network."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from app.config import settings
from app.services import repository_sync as rs
from app.services.repository_sync import RepositorySyncService


def _git(cwd: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": "Test Author", "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test Author", "GIT_COMMITTER_EMAIL": "test@example.com",
    })
    out = subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _make_remote(root: Path, branch: str, files: dict[str, str]) -> tuple[Path, str]:
    """A local repository with one commit on `branch`; returns (path, head sha)."""
    remote = root / f"remote_{branch}"
    remote.mkdir()
    _git(remote, "init", "-q", "-b", branch)
    for rel, content in files.items():
        p = remote / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    _git(remote, "add", "-A")
    _git(remote, "commit", "-q", "-m", "initial")
    return remote, _git(remote, "rev-parse", "HEAD")


@pytest.fixture
def repos_dir(tmp_path, monkeypatch):
    target = tmp_path / "repos"
    target.mkdir()
    monkeypatch.setattr(settings, "repos_dir", target)
    return target


@pytest.mark.asyncio
async def test_full_clone_records_commit_and_status(db_session, repos_dir, tmp_path, monkeypatch):
    remote, sha = _make_remote(tmp_path, "master", {"rules/a.yml": "title: a\n"})
    svc = RepositorySyncService(db_session)
    monkeypatch.setitem(svc.REPO_CONFIGS["sigma"], "url", str(remote))

    ok, message = await svc.sync_repository("sigma")
    assert ok and message == "Cloned sigma repository"
    assert (repos_dir / "sigma" / "rules" / "a.yml").exists()
    repo = await svc.get_repository("sigma")
    assert repo.last_commit_hash == sha and repo.status == "idle" and repo.last_sync_at is not None
    assert svc.get_current_commit("sigma") == sha


@pytest.mark.asyncio
async def test_existing_checkout_is_replaced_by_a_fresh_clone(db_session, repos_dir, tmp_path, monkeypatch):
    remote, sha = _make_remote(tmp_path, "master", {"rules/a.yml": "title: a\n"})
    stale = repos_dir / "sigma"
    stale.mkdir()
    (stale / "leftover.txt").write_text("old", encoding="utf-8")
    svc = RepositorySyncService(db_session)
    monkeypatch.setitem(svc.REPO_CONFIGS["sigma"], "url", str(remote))

    ok, _ = await svc.sync_repository("sigma")
    assert ok
    assert not (stale / "leftover.txt").exists()
    assert (stale / "rules" / "a.yml").exists()


@pytest.mark.asyncio
async def test_sparse_clone_checks_out_only_the_patterns_on_the_configured_branch(db_session, repos_dir, tmp_path, monkeypatch):
    remote, sha = _make_remote(tmp_path, "develop", {
        "rules/keep/one.yml": "title: one\n",
        "rules/keep/two.yml": "title: two\n",
        "other/skip.yml": "title: skip\n",
        "README.md": "readme\n",
    })
    svc = RepositorySyncService(db_session)
    monkeypatch.setitem(svc.REPO_CONFIGS, "sparse_test", {"url": remote.as_uri(), "name": "sparse_test"})
    monkeypatch.setitem(rs.SPARSE_CHECKOUT_PATTERNS, "sparse_test", ["rules/keep/*"])
    monkeypatch.setitem(rs.SPARSE_CHECKOUT_BRANCHES, "sparse_test", "develop")

    ok, message = await svc.sync_repository("sparse_test")
    assert ok, message
    assert message == "Sparse cloned sparse_test repository"
    checkout = repos_dir / "sparse_test"
    assert (checkout / "rules" / "keep" / "one.yml").exists()
    assert (checkout / "rules" / "keep" / "two.yml").exists()
    assert not (checkout / "other" / "skip.yml").exists()
    assert _git(checkout, "rev-parse", "--abbrev-ref", "HEAD") == "develop"
    assert (await svc.get_repository("sparse_test")).last_commit_hash == sha
    assert (checkout / ".git" / "info" / "sparse-checkout").read_text(encoding="utf-8").strip() == "rules/keep/*"


@pytest.mark.asyncio
async def test_git_failure_marks_the_repository_errored(db_session, repos_dir, tmp_path, monkeypatch):
    svc = RepositorySyncService(db_session)
    monkeypatch.setitem(svc.REPO_CONFIGS["sigma"], "url", str(tmp_path / "does-not-exist"))

    ok, message = await svc.sync_repository("sigma")
    assert not ok and "error" in message.lower()
    repo = await svc.get_repository("sigma")
    assert repo.status == "error" and repo.error_message
    assert svc.get_current_commit("sigma") is None


@pytest.mark.asyncio
async def test_unknown_repository_is_rejected(db_session, repos_dir):
    svc = RepositorySyncService(db_session)
    assert await svc.sync_repository("nope") == (False, "Unknown repository: nope")
