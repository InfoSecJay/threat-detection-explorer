"""`created_at` is "first seen by the site" and must survive re-ingest.

Every nightly sync re-normalizes every rule and upserts it with
session.merge(); the fresh row carried created_at=utcnow(), so merge()
reset first-seen to the last sync for the whole corpus (and tombstones
inherited that as first_seen_at). The store step now carries the stored
value over.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.services.ingestion import IngestionService
from app.services.ingestion_errors import IngestionStats


def _rule(id_: str, run: str, created_at: datetime, title: str = "Rule title") -> Detection:
    return Detection(
        id=id_, source="sigma", source_file=f"{id_}.yml", source_repo_url="https://x",
        title=title, detection_logic="selection: x", language="sigma", raw_content="raw",
        severity="high", status="stable", rule_id=f"rid-{id_}", mitre_techniques=["T1059"],
        sync_run_id=run, created_at=created_at, updated_at=created_at,
    )


@pytest.mark.asyncio
async def test_store_keeps_first_seen_across_resyncs(db_session):
    first = datetime(2026, 8, 1, 6, 0, tzinfo=timezone.utc)
    later = first + timedelta(days=30)
    db_session.add(_rule("keep", run="run-1", created_at=first))
    await db_session.commit()

    svc = IngestionService(db_session)
    # The re-ingested row is a NEW object with today's timestamps and a
    # changed title, exactly what the nightly sync produces.
    stored = await svc._store_rules_safe(
        [_rule("keep", run="run-2", created_at=later, title="Rule title (edited)"),
         _rule("fresh", run="run-2", created_at=later)],
        IngestionStats(),
    )
    assert stored == 2

    db_session.expire_all()
    rows = {r.id: r for r in (await db_session.execute(select(Detection))).scalars().all()}
    kept, fresh = rows["keep"], rows["fresh"]
    assert kept.title == "Rule title (edited)"          # the update still lands
    assert kept.sync_run_id == "run-2"
    assert kept.created_at.replace(tzinfo=None) == first.replace(tzinfo=None)  # first seen preserved
    assert fresh.created_at.replace(tzinfo=None) == later.replace(tzinfo=None)  # brand-new rule keeps its own
