"""Integration tests for IngestionService — focus on the atomic-swap pattern.

The flow under test:

  1. ``_store_rules_safe`` upserts a batch via SQLAlchemy ``merge()``,
     stamping each row's ``updated_at`` to ``utcnow()``.
  2. ``_cleanup_stale_rules`` deletes any row of the given source whose
     ``updated_at < ingest_start`` — i.e. rows the current ingest did
     not touch.

The dangerous predecessor was DELETE-then-INSERT, which wiped the source
table before the new rows were committed; a process crash between the
two left the source at zero rows. Production lost the entire sentinel
catalog this way on 2026-04-11. These tests pin the current safe
behaviour so a future refactor can't regress to that pattern.

Test strategy:
  - Use the in-memory ``db_session`` fixture from conftest.py.
  - Construct ``Detection`` rows directly (skip the parse → normalize
    pipeline; that's exercised by the parser/normalizer suites).
  - Build a thin ``IngestionService`` wrapper that gives us direct
    access to the private helpers without spinning up the full
    parser / normalizer / git stack — we're testing storage, not
    discovery.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.utils.datetime_utils import utcnow


def _detection(
    *,
    id_: str,
    source: str = "sigma",
    title: str = "Sample rule",
    severity: str = "medium",
    updated_at=None,
) -> Detection:
    """Build a minimally-populated Detection row.

    Defaults satisfy every NOT NULL column; tests only need to override
    fields they specifically care about.
    """
    return Detection(
        id=id_,
        source=source,
        source_file=f"{source}/{id_}.yml",
        source_repo_url=f"https://example.test/{source}",
        title=title,
        severity=severity,
        status="stable",
        language="sigma",
        detection_logic="placeholder",
        raw_content="placeholder",
        mitre_tactics=[],
        mitre_techniques=[],
        tags=[],
        platforms=[],
        data_sources=[],
        event_types=[],
        extracted_event_ids=[],
        extracted_process_names=[],
        extracted_api_actions=[],
        # `updated_at` defaults to utcnow() at insert time. We override
        # it in tests that need to simulate a "stale" row from a prior
        # ingest run.
        **({"updated_at": updated_at} if updated_at else {}),
    )


@pytest.fixture
def ingestion_service(db_session):
    """An IngestionService bound to the in-memory test session.

    We construct it without going through the standard parser /
    normalizer / git wiring because:
      - Those subsystems have their own test suites.
      - Constructing the real service would try to resolve repo paths
        on disk and fail when there's no clone.
    Instead, we monkey-attach the private helpers we want to exercise
    onto a bare object that holds the session as `.db`.
    """
    from app.services.ingestion import IngestionService

    # Bypass __init__ — it eagerly builds 8 parsers + 8 normalizers,
    # all of which expect on-disk repo paths to exist.
    svc = IngestionService.__new__(IngestionService)
    svc.db = db_session
    return svc


# ── _store_rules_safe ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_rules_inserts_new_rows(ingestion_service, db_session):
    from app.services.ingestion_errors import IngestionStats

    stats = IngestionStats()
    rules = [_detection(id_=f"new-{i}") for i in range(3)]
    stored = await ingestion_service._store_rules_safe(rules, stats)

    assert stored == 3
    assert stats.error_count == 0
    rows = (await db_session.execute(select(Detection))).scalars().all()
    assert {r.id for r in rows} == {"new-0", "new-1", "new-2"}


@pytest.mark.asyncio
async def test_store_rules_upserts_existing_rows(ingestion_service, db_session):
    """Re-storing an existing id MUST update in place (merge), not duplicate."""
    from app.services.ingestion_errors import IngestionStats

    stats = IngestionStats()
    db_session.add(_detection(id_="rule-1", title="original title"))
    await db_session.commit()

    updated = _detection(id_="rule-1", title="new title")
    stored = await ingestion_service._store_rules_safe([updated], stats)

    assert stored == 1
    rows = (await db_session.execute(select(Detection))).scalars().all()
    assert len(rows) == 1, "merge() must not insert a duplicate"
    assert rows[0].title == "new title"


@pytest.mark.asyncio
async def test_store_rules_updates_updated_at_on_upsert(ingestion_service, db_session):
    """The atomic-swap pattern relies on `updated_at` advancing on every
    touched row so cleanup can identify stale rows by date. Confirm
    upsert refreshes it.

    Note: the production code constructs each Detection with
    ``updated_at=utcnow()`` in `_to_detection_model`, so the new row's
    timestamp is set explicitly at construction time, not via the
    SQLAlchemy ``onupdate`` hook. We pin that contract here.
    """
    from app.services.ingestion_errors import IngestionStats

    stats = IngestionStats()
    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="rule-1", updated_at=long_ago))
    await db_session.commit()

    before = utcnow() - timedelta(seconds=1)
    # Match the production pattern: explicit updated_at on the new row.
    fresh = _detection(id_="rule-1")
    fresh.updated_at = utcnow()
    await ingestion_service._store_rules_safe([fresh], stats)

    refreshed = (
        await db_session.execute(select(Detection).where(Detection.id == "rule-1"))
    ).scalar_one()
    assert refreshed.updated_at >= before, "updated_at must advance on upsert"


# ── _cleanup_stale_rules ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cleanup_removes_rows_older_than_ingest_start(
    ingestion_service, db_session
):
    """Old row (from a previous ingest) gets pruned; fresh row survives."""
    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="stale", updated_at=long_ago))
    db_session.add(_detection(id_="fresh"))  # default updated_at = now
    await db_session.commit()

    ingest_start = utcnow() - timedelta(seconds=1)
    await ingestion_service._cleanup_stale_rules("sigma", ingest_start)

    surviving = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert surviving == {"fresh"}


@pytest.mark.asyncio
async def test_cleanup_only_touches_target_source(ingestion_service, db_session):
    """Cleanup must scope its DELETE to the source being ingested.
    A regression that drops the source filter would wipe other sources'
    rules with old `updated_at`."""
    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="sigma-old",  source="sigma",  updated_at=long_ago))
    db_session.add(_detection(id_="splunk-old", source="splunk", updated_at=long_ago))
    await db_session.commit()

    await ingestion_service._cleanup_stale_rules("sigma", utcnow())

    surviving = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert "splunk-old" in surviving, "cleanup must NOT touch other sources"
    assert "sigma-old" not in surviving


# ── End-to-end atomic-swap behaviour ───────────────────────────────────


@pytest.mark.asyncio
async def test_atomic_swap_full_cycle(ingestion_service, db_session):
    """Simulate two consecutive ingests and verify the swap semantics:
      - First ingest stores rules A, B, C.
      - Second ingest stores B (unchanged), C (updated), D (new).
      - Final state should be {B, C-updated, D} — A pruned because it
        wasn't in the second ingest, C is the updated copy, D is new."""
    from app.services.ingestion_errors import IngestionStats

    # First ingest. Capture ingest_start BEFORE the rows land — that's
    # what production does in `ingest_repository`. The new rows then
    # have updated_at >= ingest_start and the cleanup leaves them alone.
    ingest1_start = utcnow() - timedelta(seconds=1)
    stats1 = IngestionStats()
    rules1 = [_detection(id_="A"), _detection(id_="B"), _detection(id_="C")]
    for r in rules1:
        r.updated_at = utcnow()  # production sets this in _to_detection_model
    await ingestion_service._store_rules_safe(rules1, stats1)
    await ingestion_service._cleanup_stale_rules("sigma", ingest1_start)
    initial = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert initial == {"A", "B", "C"}

    # Second ingest — A absent, C updated, D added.
    # ingest2_start must come AFTER the first ingest's updated_at
    # stamps. In production the gap is minutes; in tests the two ingests
    # run within microseconds, so we explicitly anchor ingest2_start
    # past the latest first-ingest write.
    ingest2_start = utcnow() + timedelta(milliseconds=10)
    stats2 = IngestionStats()
    rules2 = [
        _detection(id_="B"),
        _detection(id_="C", title="updated C"),
        _detection(id_="D"),
    ]
    for r in rules2:
        r.updated_at = ingest2_start + timedelta(milliseconds=1)
    await ingestion_service._store_rules_safe(rules2, stats2)
    await ingestion_service._cleanup_stale_rules("sigma", ingest2_start)

    rows = {
        r.id: r for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert set(rows.keys()) == {"B", "C", "D"}, "A should be pruned, D should be added"
    assert rows["C"].title == "updated C", "C should reflect the second ingest's content"


@pytest.mark.asyncio
async def test_crash_before_cleanup_preserves_old_rows(
    ingestion_service, db_session
):
    """Critical safety property: if the process crashes AFTER store but
    BEFORE cleanup, the old rows survive. The OLD DELETE-first pattern
    failed this — production sentinel was wiped to 0 rows on
    2026-04-11 because of it. This test pins the current safe behaviour."""
    from app.services.ingestion_errors import IngestionStats

    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="old-survivor", updated_at=long_ago))
    db_session.add(_detection(id_="old-prunable", updated_at=long_ago))
    await db_session.commit()

    # Store one new rule; "crash" before _cleanup_stale_rules runs.
    stats = IngestionStats()
    await ingestion_service._store_rules_safe([_detection(id_="new-rule")], stats)

    # No cleanup happened. All three rows must coexist — old data is
    # not lost just because the new ingest didn't finish.
    rows = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert rows == {"old-survivor", "old-prunable", "new-rule"}, (
        "mid-ingest crash must NOT wipe old rows"
    )


# ── _validate_date ──────────────────────────────────────────────────────


def test_validate_date_rejects_future_dates():
    from app.services.ingestion import IngestionService

    future = utcnow() + timedelta(days=365)
    assert IngestionService._validate_date(future) is None


def test_validate_date_passes_past_dates_through():
    from app.services.ingestion import IngestionService

    past = utcnow() - timedelta(days=10)
    assert IngestionService._validate_date(past) == past


def test_validate_date_passes_none_through():
    from app.services.ingestion import IngestionService

    assert IngestionService._validate_date(None) is None
