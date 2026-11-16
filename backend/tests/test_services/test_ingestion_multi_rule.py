"""Files that carry several rules go through `ingest_repository` whole.

GitLab TLDR is the first source where one file yields more than one
catalog row. These tests drive the real service loop (discovery ->
parse_all -> normalize -> store -> cleanup) over a fixture clone and pin
what that changes:

- every Sigma document is stored, under its own id;
- `discovered` counts rules, so the stale-row circuit breaker (which
  compares it with the previous rule count) does not trip on the second
  sync of a source that has more rules than files;
- a rule removed from a file that still exists is cleaned up.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.config import Settings
from app.models.detection import Detection
from app.models.repository import Repository
from app.parsers.base import BaseParser, ParsedRule, SkippedRule
from app.services.ingestion import IngestionService

from tests.test_parsers.test_gitlab import BULK_ACCESS_MD, LFI_MD

_DIR = "Detections/platforms/GitLab"


@pytest.fixture
def gitlab_repo(monkeypatch, tmp_path):
    repos_root = tmp_path / "repos"
    repo = repos_root / "gitlab"
    (repo / _DIR / "Threat Detections").mkdir(parents=True)
    (repo / _DIR / "Vulnerability Detections").mkdir(parents=True)
    (repo / _DIR / "Threat Detections" / "bulk_access.md").write_text(BULK_ACCESS_MD, encoding="utf-8")
    (repo / _DIR / "Vulnerability Detections" / "lfi_probe.md").write_text(LFI_MD, encoding="utf-8")
    # Not detections: must be neither discovered nor counted.
    (repo / "README.md").write_text("# TLDR\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "CONTRACT.md").write_text("```yaml\nlogsource: {}\n```\n", encoding="utf-8")
    monkeypatch.setattr(Settings, "get_repo_path", lambda self, name: repos_root / name)

    async def _noop():
        return None

    from app.services.mitre import mitre_service

    monkeypatch.setattr(mitre_service, "ensure_loaded", _noop)
    return repo


async def _rows(db):
    return (await db.execute(select(Detection).where(Detection.source == "gitlab"))).scalars().all()


@pytest.mark.asyncio
async def test_every_document_of_every_file_is_stored(db_session, gitlab_repo):
    stats = await IngestionService(db_session).ingest_repository("gitlab")

    rows = await _rows(db_session)
    assert len(rows) == 5  # 4 documents in one file + 1 in the other
    assert len({r.id for r in rows}) == 5
    assert len({r.source_file for r in rows}) == 2
    assert stats.parsed == stats.normalized == stats.stored == 5
    # Counted in rules, not files, so the rate is a rate.
    assert stats.discovered == 5
    assert stats.success_rate == 100.0
    assert stats.errors == []
    assert stats.taxonomy_unmatched_count == 0
    assert stats.taxonomy_no_datasource_count == 0


@pytest.mark.asyncio
async def test_second_sync_is_idempotent(db_session, gitlab_repo):
    db_session.add(Repository(name="gitlab", url="https://gitlab.com/x/y.git", status="idle", rule_count=0))
    await db_session.commit()
    svc = IngestionService(db_session)
    await svc.ingest_repository("gitlab")
    first = {r.id for r in await _rows(db_session)}

    repo = (await db_session.execute(select(Repository).where(Repository.name == "gitlab"))).scalar_one()
    assert repo.rule_count == 5
    stats = await svc.ingest_repository("gitlab")

    assert {r.id for r in await _rows(db_session)} == first
    assert stats.errors == []


@pytest.mark.asyncio
async def test_breaker_compares_rules_with_rules(db_session, gitlab_repo):
    """The breaker compares discovery with the previous RULE count. 12
    previous rules against 5 now is a real drop and trips. 12 against
    10 rules in 4 files is healthy: counted in files (4 < 9) it would
    trip on every sync of a source with more rules than files."""
    svc = IngestionService(db_session)
    db_session.add(Repository(name="gitlab", url="https://gitlab.com/x/y.git", status="idle", rule_count=12))
    await db_session.commit()
    stats = await svc.ingest_repository("gitlab")
    assert [e for e in stats.errors if "CIRCUIT BREAKER" in e.message]

    repo = (await db_session.execute(select(Repository).where(Repository.name == "gitlab"))).scalar_one()
    repo.rule_count, repo.status, repo.error_message = 12, "idle", None
    await db_session.commit()
    # Pad the fixture to 10 rules in 4 files, each with fresh Sigma ids.
    threat_dir = gitlab_repo / _DIR / "Threat Detections"
    (threat_dir / "bulk_access_copy.md").write_text(BULK_ACCESS_MD.replace("-4", "-5"), encoding="utf-8")
    (threat_dir / "lfi_probe_copy.md").write_text(LFI_MD.replace("-4555-", "-5555-"), encoding="utf-8")
    stats = await svc.ingest_repository("gitlab")
    assert stats.discovered == 10
    assert not [e for e in stats.errors if "CIRCUIT BREAKER" in e.message]


@pytest.mark.asyncio
async def test_rule_removed_from_a_surviving_file_is_cleaned_up(db_session, gitlab_repo):
    svc = IngestionService(db_session)
    await svc.ingest_repository("gitlab")
    path = gitlab_repo / _DIR / "Threat Detections" / "bulk_access.md"
    text = path.read_text(encoding="utf-8")
    # Drop the supplementary fence (the correlation of correlations).
    start = text.index("Where correlations of correlations are supported")
    end = text.index("### Raw Log Query")
    path.write_text(text[:start] + text[end:], encoding="utf-8")

    await svc.ingest_repository("gitlab")

    titles = {r.title for r in await _rows(db_session)}
    assert "GitLab bulk repository harvesting" not in titles
    assert len(titles) == 4


@pytest.mark.asyncio
async def test_file_without_sigma_is_one_parse_failure(db_session, gitlab_repo):
    (gitlab_repo / _DIR / "Threat Detections" / "draft.md").write_text(
        "# About\n\n## Detection\n\nNot written yet.\n", encoding="utf-8",
    )
    stats = await IngestionService(db_session).ingest_repository("gitlab")
    assert stats.stored == 5
    assert [e.file_path.replace("\\", "/") for e in stats.parse_failures] == [
        f"{_DIR}/Threat Detections/draft.md"
    ]


# -- the default parse_all keeps single-rule parsers' contract ---------------


class _OneRule(BaseParser):
    def __init__(self, result):
        self._result = result

    @property
    def source_name(self) -> str:
        return "sigma"

    def can_parse(self, file_path) -> bool:
        return True

    def parse(self, file_path, content):
        return self._result


def test_default_parse_all_wraps_parse():
    rule = ParsedRule(source="sigma", file_path="a.yml", raw_content="", title="t", detection_logic_raw={})
    assert _OneRule(rule).parse_all("a.yml", "") == [rule]
    assert _OneRule(None).parse_all("a.yml", "") is None
    skipped = SkippedRule("stub")
    assert _OneRule(skipped).parse_all("a.yml", "") is skipped
