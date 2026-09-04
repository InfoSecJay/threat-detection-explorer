"""Rule history timeline (#127): the last touches of a rule file from
upstream git, stored on the row and served on the detail endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.git_service import GitService


def test_history_parsing_is_newest_first_and_bounded():
    out = (
        "aaa\x1fAlice\x1f2026-08-01T10:00:00+00:00\x1ffix: tighten filter\n"
        "bbb\x1fBob\x1f2026-03-01T10:00:00+02:00\x1frefactor\n"
        "\n"
        "ccc\x1fCarol\x1f2025-01-01T00:00:00Z\n"  # no subject
        "garbage line without separators\n"
    )
    touches = GitService._parse_history(out)
    assert [t["sha"] for t in touches] == ["aaa", "bbb", "ccc"]
    assert touches[0] == {"sha": "aaa", "author": "Alice", "date": "2026-08-01T10:00:00+00:00", "subject": "fix: tighten filter"}
    assert touches[2]["subject"] == ""
    assert GitService._parse_history(None) == [] and GitService._parse_history("") == []


def test_get_file_history_passes_limit_and_follow(monkeypatch, tmp_path: Path):
    svc = GitService(tmp_path)
    seen: dict = {}

    def fake_run(args):
        seen["args"] = args
        return "abc\x1fA\x1f2026-01-01T00:00:00Z\x1fs"

    monkeypatch.setattr(svc, "_run_git_log", fake_run)
    touches = svc.get_file_history("rules/windows/a.yml", limit=5)
    assert touches[0]["sha"] == "abc"
    assert seen["args"][:2] == ["log", "--follow"]
    assert "-n5" in seen["args"] and seen["args"][-1].endswith("rules/windows/a.yml")


def test_normalizer_attaches_history_from_git(tmp_path: Path, monkeypatch):
    from app.normalizers.base import NormalizedDetection
    from app.normalizers.sigma import SigmaNormalizer

    n = SigmaNormalizer("https://github.com/SigmaHQ/sigma.git", tmp_path)
    assert n._git_service is not None
    monkeypatch.setattr(
        n._git_service, "get_file_history",
        lambda path, limit=10: [{"sha": "abc", "author": "A", "date": "2026-01-01T00:00:00Z", "subject": path}],
    )
    nd = NormalizedDetection(
        id="x", source="sigma", source_file="rules/a.yml", source_repo_url="u", title="t",
        description="d", author="a", status="stable", severity="high",
        detection_logic="d", language="sigma", raw_content="r",
    )
    n.attach_upstream_history(nd, "rules/a.yml")
    assert nd.upstream_history[0]["subject"] == "rules/a.yml"

    # No git service (repo path None) -> empty, never raises.
    bare = SigmaNormalizer("https://github.com/SigmaHQ/sigma.git", None)
    bare.attach_upstream_history(nd, "rules/a.yml")
    assert nd.upstream_history == []


def _rule(**kw) -> Detection:
    base = dict(
        id="sigma-h1", source="sigma", source_file="a.yml", source_repo_url="https://github.com/SigmaHQ/sigma.git",
        title="Rule", detection_logic="x", language="sigma", raw_content="x",
        severity="high", status="stable", platforms=["windows"], data_sources=["sysmon"],
        event_types=["process_creation"], mitre_techniques=["T1059"],
    )
    base.update(kw)
    return Detection(**base)


@pytest.mark.asyncio
async def test_detail_serves_history_and_tolerates_legacy_null(db_session):
    touches = [{"sha": "abc", "author": "Alice", "date": "2026-08-01T10:00:00+00:00", "subject": "fix"}]
    db_session.add_all([_rule(upstream_history=touches), _rule(id="sigma-h2", upstream_history=None)])
    await db_session.commit()

    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/detections/sigma-h1")
            assert r.status_code == 200 and r.json()["upstream_history"] == touches
            r2 = await c.get("/api/v1/detections/sigma-h2")
            assert r2.status_code == 200 and r2.json()["upstream_history"] == []
            # The slim list never carries history.
            lst = await c.get("/api/v1/detections?limit=5")
            assert lst.status_code == 200 and all("upstream_history" not in i for i in lst.json()["items"])
    finally:
        app.dependency_overrides.pop(get_db, None)
