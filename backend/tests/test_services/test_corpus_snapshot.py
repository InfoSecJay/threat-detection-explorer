"""Nightly corpus snapshots (#94 / S5.1): write, overwrite, read back."""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import func, select

from app.models.corpus_snapshot import CorpusSnapshot
from app.models.detection import Detection
from app.services.corpus_snapshot import read_corpus_snapshot, write_corpus_snapshot


def _rule(i: int, source: str = "sigma") -> Detection:
    return Detection(
        id=f"{source}-{i}", source=source, source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i} with unicode → and detail", detection_logic="selection: x",
        language="sigma", raw_content="title: x\ndetection: y", severity="high", status="stable",
        mitre_techniques=["T1059.001"], quality_score=70,
    )


@pytest.mark.asyncio
async def test_snapshot_round_trips_every_rule(db_session):
    db_session.add_all([_rule(1), _rule(2), _rule(3, source="elastic")])
    await db_session.commit()

    day = date(2026, 8, 31)
    counts = await write_corpus_snapshot(db_session, snapshot_date=day)
    assert counts == {"elastic": 1, "sigma": 2}

    back = await read_corpus_snapshot(db_session, day, "sigma")
    assert len(back) == 2
    ids = {r["id"] for r in back}
    assert ids == {"sigma-1", "sigma-2"}
    one = next(r for r in back if r["id"] == "sigma-1")
    assert one["title"].startswith("Rule 1 with unicode")
    assert one["mitre_techniques"] == ["T1059.001"]
    assert one["raw_content"] == "title: x\ndetection: y"
    assert "sync_run_id" not in one  # bookkeeping excluded


@pytest.mark.asyncio
async def test_same_day_rerun_overwrites_not_duplicates(db_session):
    db_session.add(_rule(1))
    await db_session.commit()
    day = date(2026, 8, 31)
    await write_corpus_snapshot(db_session, snapshot_date=day)

    db_session.add(_rule(2))
    await db_session.commit()
    await write_corpus_snapshot(db_session, snapshot_date=day)

    n = (
        await db_session.execute(
            select(func.count()).select_from(CorpusSnapshot).where(
                CorpusSnapshot.snapshot_date == day, CorpusSnapshot.source == "sigma",
            )
        )
    ).scalar()
    assert n == 1
    assert len(await read_corpus_snapshot(db_session, day, "sigma")) == 2


@pytest.mark.asyncio
async def test_missing_snapshot_reads_empty(db_session):
    assert await read_corpus_snapshot(db_session, date(2020, 1, 1), "sigma") == []
