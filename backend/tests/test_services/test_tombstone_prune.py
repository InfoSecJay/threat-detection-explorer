"""Tombstone hygiene (#133): rows shadowed by a live rule are pruned."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.models.removed_detection import RemovedDetection
from app.services.ingestion import IngestionService
from app.services.tombstones import get_tombstone, make_tombstone, prune_shadowed_tombstones


def _rule(id_: str, rule_id: str | None, run: str = "r1", title: str = "Rule") -> Detection:
    return Detection(
        id=id_, source="sigma", source_file=f"{id_}.yml", source_repo_url="https://x",
        title=title, detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", rule_id=rule_id, mitre_techniques=["T1059"], sync_run_id=run,
    )


@pytest.mark.asyncio
async def test_prune_keeps_only_tombstones_with_no_live_counterpart(db_session):
    db_session.add_all([
        make_tombstone(_rule("gone", "rid-gone", title="Really removed")),
        make_tombstone(_rule("back", "rid-back", title="Came back")),        # same id is live again
        make_tombstone(_rule("old-key", "rid-rekey", title="Re-keyed")),     # live under a new id
        make_tombstone(_rule("noid", None, title="No upstream id, gone")),
        _rule("back", "rid-back", title="Came back"),
        _rule("new-key", "rid-rekey", title="Re-keyed"),
    ])
    await db_session.commit()

    assert await prune_shadowed_tombstones(db_session) == 2
    await db_session.commit()

    left = sorted((await db_session.execute(select(RemovedDetection.id))).scalars().all())
    assert left == ["gone", "noid"]
    # The genuinely removed rule still serves its 410 page.
    assert (await get_tombstone(db_session, "gone"))["title"] == "Really removed"
    assert (await get_tombstone(db_session, "rid-gone"))["id"] == "gone"


@pytest.mark.asyncio
async def test_stale_cleanup_prunes_after_tombstoning(db_session):
    """The sync path: a rule dropped upstream gets a tombstone that
    survives the prune; a tombstone for a rule the same run re-stored
    does not."""
    db_session.add_all([
        _rule("dropped", "rid-dropped", run="old"),
        _rule("kept", "rid-kept", run="new"),
        make_tombstone(_rule("kept", "rid-kept", title="Kept but tombstoned last night")),
    ])
    await db_session.commit()

    await IngestionService(db_session)._cleanup_stale_rules("sigma", "new")

    left = sorted((await db_session.execute(select(RemovedDetection.id))).scalars().all())
    assert left == ["dropped"]
    assert await db_session.get(Detection, "dropped") is None
    assert await db_session.get(Detection, "kept") is not None
