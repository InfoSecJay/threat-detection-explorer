"""Upstream links pin the indexed commit; the methodology prints the
real branch (DX-15 / #157)."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from app.api.schemas import DetectionResponse
from app.models.detection import Detection
from app.normalizers.sigma import SigmaNormalizer
from app.services.repository_sync import ALL_REPOSITORY_NAMES
from app.services.upstream_refs import REPO_BRANCHES, branch_for, latest_upstream_url, pinned_commit

SHA = "ffc8ad66" + "0" * 32
PINNED = f"https://github.com/elastic/detection-rules/blob/{SHA}/rules/windows/x.toml"


def test_every_source_has_a_branch():
    assert set(REPO_BRANCHES) == set(ALL_REPOSITORY_NAMES)
    # The three the review called out, plus the sparse-clone trio.
    assert branch_for("elastic") == "main"
    assert branch_for("splunk") == "develop"
    assert branch_for("sigma") == "master"
    assert branch_for("google_secops") == "main"
    assert branch_for("panther") == "develop"
    assert branch_for("sentinel") == "master"


def test_latest_url_swaps_the_pinned_sha_for_the_branch():
    assert latest_upstream_url("elastic", PINNED) == (
        "https://github.com/elastic/detection-rules/blob/main/rules/windows/x.toml"
    )
    assert pinned_commit(PINNED) == SHA
    # A branch link (rows indexed before DX-15) has no second link to offer.
    branch_link = "https://github.com/SigmaHQ/sigma/blob/master/rules/r.yml"
    assert latest_upstream_url("sigma", branch_link) is None
    assert pinned_commit(branch_link) is None
    assert latest_upstream_url("sigma", None) is None and latest_upstream_url("sigma", "") is None
    # A short or non-hex "ref" is not a pin.
    assert pinned_commit("https://x/blob/ffc8ad66/rules/r.yml") is None


@pytest.fixture
def clone(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "sigma"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    subprocess.run(["git", "init", "-b", "master"], cwd=repo, check=True, capture_output=True)
    (repo / "rules").mkdir()
    (repo / "rules" / "r.yml").write_text("title: r\n", encoding="utf-8")
    subprocess.run(["git", "add", "rules/r.yml"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add"], cwd=repo, check=True, capture_output=True, env=env)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    return repo, sha


def test_normalizer_pins_the_link_when_a_clone_is_on_disk(clone):
    repo, sha = clone
    n = SigmaNormalizer("https://github.com/SigmaHQ/sigma.git", repo)
    assert n.build_source_rule_url("rules\\r.yml", "sigma") == f"https://github.com/SigmaHQ/sigma/blob/{sha}/rules/r.yml"
    # The moving link is derived from the pinned one, never stored.
    assert latest_upstream_url("sigma", n.build_source_rule_url("rules/r.yml", "sigma")).endswith("/blob/master/rules/r.yml")


def test_normalizer_falls_back_to_the_branch_without_a_clone():
    n = SigmaNormalizer("https://github.com/SigmaHQ/sigma")
    assert n.build_source_rule_url("/rules/r.yml", "sigma") == "https://github.com/SigmaHQ/sigma/blob/master/rules/r.yml"
    # The fallback follows the map, not a per-normalizer literal.
    assert n.build_source_rule_url("rules/r.yml", "splunk").endswith("/blob/develop/rules/r.yml")


def _detection(url: str | None) -> Detection:
    now = datetime(2026, 9, 11, 0, 0, 0)
    return Detection(
        id="elastic-1", source="elastic", source_file="rules/windows/x.toml",
        source_repo_url="https://github.com/elastic/detection-rules", source_rule_url=url,
        title="x", detection_logic="x", language="eql", raw_content="x", severity="high", status="stable",
        created_at=now, updated_at=now,
    )


def test_detail_response_offers_the_latest_link_only_for_pinned_rows():
    pinned = DetectionResponse.from_detection(_detection(PINNED))
    assert pinned.source_rule_url == PINNED
    assert pinned.source_rule_url_latest == "https://github.com/elastic/detection-rules/blob/main/rules/windows/x.toml"

    legacy = DetectionResponse.from_detection(_detection("https://github.com/elastic/detection-rules/blob/main/rules/windows/x.toml"))
    assert legacy.source_rule_url_latest is None
    assert DetectionResponse.from_detection(_detection(None)).source_rule_url_latest is None
