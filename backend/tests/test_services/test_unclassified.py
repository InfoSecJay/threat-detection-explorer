"""Unclassified burn-down (teardown R14 / #112)."""

from __future__ import annotations

from datetime import date

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.models.unclassified_snapshot import UnclassifiedSnapshot
from app.services.corpus_snapshot import write_corpus_snapshot
from app.services.unclassified import (
    UNCLASSIFIED_FIELDS,
    build_report,
    current_counts,
    history,
    write_unclassified_snapshot,
)


def _rule(i: int, source: str = "sigma", **kw) -> Detection:
    base = dict(
        id=f"{source}-{i}", source=source, source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i}", detection_logic="x", language="sigma", raw_content="x",
        severity="high", status="stable", platforms=["windows"], data_sources=["sysmon"],
        event_types=["process_creation"], mitre_techniques=["T1059"],
    )
    base.update(kw)
    return Detection(**base)


@pytest.mark.asyncio
async def test_current_counts_per_source_and_field(db_session):
    db_session.add_all([
        _rule(1),
        _rule(2, platforms=["unknown"], status="unknown", mitre_techniques=[]),
        _rule(3, source="sublime", status="not_applicable", language="none", event_types=["unknown", "email_message"]),
    ])
    await db_session.commit()
    c = await current_counts(db_session)
    assert c["sigma"] == {"_total": 2, "platforms": 1, "status": 1, "mitre_techniques": 1}
    # not_applicable / none are deliberate values, never unclassified.
    assert c["sublime"] == {"_total": 1, "event_types": 1}


@pytest.mark.asyncio
async def test_snapshot_writes_today_and_backfills_from_corpus_snapshots(db_session):
    db_session.add_all([_rule(1, platforms=["unknown"]), _rule(2)])
    await db_session.commit()
    # A corpus snapshot exists for an earlier day with no burn-down rows.
    await write_corpus_snapshot(db_session, snapshot_date=date(2026, 8, 31))

    written = await write_unclassified_snapshot(db_session, snapshot_date=date(2026, 9, 2))
    assert set(written) == {"2026-08-31", "2026-09-02"}
    assert written["2026-09-02"] == len(UNCLASSIFIED_FIELDS)  # one source

    rows = (await db_session.execute(select(UnclassifiedSnapshot))).scalars().all()
    plat = {r.snapshot_date: r.rule_count for r in rows if r.field == "platforms"}
    assert plat == {date(2026, 8, 31): 1, date(2026, 9, 2): 1}
    assert all(r.total_rules == 2 for r in rows)

    # Same-day rerun replaces rather than duplicates.
    await write_unclassified_snapshot(db_session, snapshot_date=date(2026, 9, 2))
    n = len((await db_session.execute(select(UnclassifiedSnapshot))).scalars().all())
    assert n == 2 * len(UNCLASSIFIED_FIELDS)

    h = await history(db_session, days=3650)
    assert [d["date"] for d in h] == ["2026-08-31", "2026-09-02"]
    assert h[-1]["fields"]["platforms"] == 1 and h[-1]["total_rules"] == 2


@pytest.mark.asyncio
async def test_report_shape_and_endpoint(db_session):
    db_session.add_all([_rule(1, severity="unknown"), _rule(2, source="splunk", data_sources=["unknown"])])
    await db_session.commit()
    report = await build_report(db_session)
    assert report["total_rules"] == 2
    assert report["totals"]["severity"] == 1 and report["totals"]["data_sources"] == 1
    assert [s["source"] for s in report["sources"]] == ["sigma", "splunk"]
    assert report["catalog_filter_key"]["data_sources"] == "data_sources_normalized"

    async def _db():
        yield db_session
    app.dependency_overrides[get_db] = _db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            r = await client.get("/api/methodology/unclassified")
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    assert r.json()["totals"]["severity"] == 1
