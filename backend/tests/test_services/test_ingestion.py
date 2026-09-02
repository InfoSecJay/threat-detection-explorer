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
from pathlib import Path

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
    sync_run_id: str | None = None,
) -> Detection:
    """Build a minimally-populated Detection row.

    Defaults satisfy every NOT NULL column; tests only need to override
    fields they specifically care about.
    """
    return Detection(
        id=id_,
        sync_run_id=sync_run_id,
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
async def test_cleanup_removes_rows_not_stamped_with_current_run(
    ingestion_service, db_session
):
    """Rows from a previous run (or with no run id at all -- written
    before the column existed) get pruned; the current run's rows
    survive. Timestamps are irrelevant (#31): the stale row is given a
    NEWER updated_at than the fresh one and must still go."""
    db_session.add(_detection(id_="stale", sync_run_id="run-old", updated_at=utcnow()))
    db_session.add(_detection(id_="legacy", sync_run_id=None))
    db_session.add(
        _detection(id_="fresh", sync_run_id="run-new", updated_at=utcnow() - timedelta(days=30))
    )
    await db_session.commit()

    await ingestion_service._cleanup_stale_rules("sigma", "run-new")

    surviving = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert surviving == {"fresh"}


@pytest.mark.asyncio
async def test_cleanup_only_touches_target_source(ingestion_service, db_session):
    """Cleanup must scope its DELETE to the source being ingested.
    A regression that drops the source filter would wipe other sources'
    rules stamped by their own runs."""
    db_session.add(_detection(id_="sigma-old",  source="sigma",  sync_run_id="run-old"))
    db_session.add(_detection(id_="splunk-old", source="splunk", sync_run_id="run-old"))
    await db_session.commit()

    await ingestion_service._cleanup_stale_rules("sigma", "run-new")

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

    # First ingest: every row stamped with this run's id (production
    # does this in _to_detection_model), then cleanup for that id.
    stats1 = IngestionStats()
    rules1 = [_detection(id_=i, sync_run_id="run-1") for i in ("A", "B", "C")]
    await ingestion_service._store_rules_safe(rules1, stats1)
    await ingestion_service._cleanup_stale_rules("sigma", "run-1")
    initial = {
        r.id for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert initial == {"A", "B", "C"}

    # Second ingest — A absent, C updated, D added. No timestamp
    # anchoring needed any more: the run id decides, however close
    # together the two ingests run.
    stats2 = IngestionStats()
    rules2 = [
        _detection(id_="B", sync_run_id="run-2"),
        _detection(id_="C", title="updated C", sync_run_id="run-2"),
        _detection(id_="D", sync_run_id="run-2"),
    ]
    await ingestion_service._store_rules_safe(rules2, stats2)
    await ingestion_service._cleanup_stale_rules("sigma", "run-2")

    rows = {
        r.id: r for r in (await db_session.execute(select(Detection))).scalars().all()
    }
    assert set(rows.keys()) == {"B", "C", "D"}, "A should be pruned, D should be added"
    assert rows["C"].title == "updated C", "C should reflect the second ingest's content"
    assert {r.sync_run_id for r in rows.values()} == {"run-2"}, (
        "every surviving row is traceable to the run that wrote it"
    )


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


# ── Circuit breaker + DB-truth count (#28) ────────────────────────────


def _make_repo(name: str, rule_count: int):
    """Build a minimally-populated Repository row for tests."""
    from app.models.repository import Repository
    return Repository(
        name=name,
        url=f"https://example.test/{name}",
        rule_count=rule_count,
        status="idle",
    )


@pytest.mark.asyncio
async def test_cleanup_guard_lets_normal_ingest_through(
    ingestion_service, db_session
):
    """Baseline: a discovery count roughly matching the previous
    rule_count passes the guard and cleanup runs normally."""
    from app.services.ingestion_errors import IngestionStats
    from app.models.repository import Repository

    # Set up previous state: 100 rules in the repo row, one stale row.
    db_session.add(_make_repo("sigma", rule_count=100))
    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="stale-rule", updated_at=long_ago))
    await db_session.commit()

    # Simulate an ingest that discovered 95 rules — small dip, well
    # inside the 20% tolerance. Guard should not fire.
    stats = IngestionStats()
    stats.discovered = 95
    ran = await ingestion_service._cleanup_stale_rules_guarded(
        "sigma", utcnow(), stats,
    )
    assert ran is True
    # Stale row was deleted.
    remaining = (await db_session.execute(select(Detection))).scalars().all()
    assert not remaining
    # Repo status stayed idle; no error.
    repo = (await db_session.execute(
        select(Repository).where(Repository.name == "sigma")
    )).scalar_one()
    assert repo.status == "idle"
    assert repo.error_message is None


@pytest.mark.asyncio
async def test_cleanup_guard_trips_on_mass_drop(
    ingestion_service, db_session
):
    """A discovery drop past the 20% threshold trips the breaker:
    cleanup is SKIPPED, an ERROR is added to stats, and the repository
    row is flagged for the UI to surface."""
    from app.services.ingestion_errors import IngestionStats
    from app.models.repository import Repository

    db_session.add(_make_repo("sigma", rule_count=100))
    long_ago = utcnow() - timedelta(days=30)
    for i in range(80):
        db_session.add(_detection(id_=f"stale-{i}", updated_at=long_ago))
    await db_session.commit()

    stats = IngestionStats()
    stats.discovered = 10   # 90% drop — far past threshold
    ran = await ingestion_service._cleanup_stale_rules_guarded(
        "sigma", utcnow(), stats,
    )
    assert ran is False, "guard should have refused to run cleanup"

    # None of the 80 stale rows were deleted.
    remaining = (await db_session.execute(select(Detection))).scalars().all()
    assert len(remaining) == 80

    # Stats now carries an ERROR with the discovery stage.
    errors = [e for e in stats.errors if e.severity.value == "error"]
    assert len(errors) == 1
    assert "CIRCUIT BREAKER" in errors[0].message
    assert errors[0].stage.value == "discovery"

    # Repository row status flipped to error with message.
    repo = (await db_session.execute(
        select(Repository).where(Repository.name == "sigma")
    )).scalar_one()
    assert repo.status == "error"
    assert repo.error_message is not None
    assert "CIRCUIT BREAKER" in repo.error_message


@pytest.mark.asyncio
async def test_cleanup_guard_trips_on_store_failures(
    ingestion_service, db_session
):
    """Rows that failed to STORE never got this run's id; cleanup would
    read them as upstream removals and tombstone live rules (the
    2026-09-02 Postgres disk-full incident: 176 Splunk rules -> 410).
    Any store-stage error skips cleanup."""
    from app.services.ingestion_errors import ErrorSeverity, ErrorStage, IngestionStats
    from app.models.repository import Repository

    db_session.add(_make_repo("sigma", rule_count=100))
    long_ago = utcnow() - timedelta(days=30)
    for i in range(5):
        db_session.add(_detection(id_=f"unstored-{i}", updated_at=long_ago))
    await db_session.commit()

    stats = IngestionStats()
    stats.discovered = 100  # discovery is fine; the database was not
    stats.add_error(
        file_path=Path("rules/x.yml"), stage=ErrorStage.STORE,
        message="Batch commit failed: connection was closed in the middle of operation",
        severity=ErrorSeverity.ERROR,
    )
    ran = await ingestion_service._cleanup_stale_rules_guarded(
        "sigma", utcnow(), stats,
    )
    assert ran is False

    remaining = (await db_session.execute(select(Detection))).scalars().all()
    assert len(remaining) == 5, "un-stored rows must survive"
    breaker = [e for e in stats.errors if "CIRCUIT BREAKER" in e.message]
    assert len(breaker) == 1 and breaker[0].stage == ErrorStage.STORE
    repo = (await db_session.execute(
        select(Repository).where(Repository.name == "sigma")
    )).scalar_one()
    assert repo.status == "error" and "store failure" in repo.error_message


@pytest.mark.asyncio
async def test_cleanup_guard_bypasses_small_corpus(
    ingestion_service, db_session
):
    """Small-corpus sources (<10 previous rules) skip the guard —
    a 3-rule source dropping to 2 shouldn't get blocked from cleanup."""
    from app.services.ingestion_errors import IngestionStats

    db_session.add(_make_repo("okta", rule_count=3))
    long_ago = utcnow() - timedelta(days=30)
    db_session.add(_detection(id_="tiny-stale", source="okta", updated_at=long_ago))
    await db_session.commit()

    stats = IngestionStats()
    stats.discovered = 1  # 66% drop, but previous < FLOOR
    ran = await ingestion_service._cleanup_stale_rules_guarded(
        "okta", utcnow(), stats,
    )
    assert ran is True
    # Stale row was deleted normally.
    remaining = (await db_session.execute(
        select(Detection).where(Detection.source == "okta")
    )).scalars().all()
    assert not remaining


@pytest.mark.asyncio
async def test_cleanup_guard_bypasses_first_ingest(
    ingestion_service, db_session
):
    """First-ever ingest (previous rule_count is 0) always passes the
    guard — there's no baseline to compare against."""
    from app.services.ingestion_errors import IngestionStats

    db_session.add(_make_repo("panther", rule_count=0))
    await db_session.commit()

    stats = IngestionStats()
    stats.discovered = 877
    ran = await ingestion_service._cleanup_stale_rules_guarded(
        "panther", utcnow(), stats,
    )
    assert ran is True


@pytest.mark.asyncio
async def test_recompute_count_reads_from_db_truth(
    ingestion_service, db_session
):
    """`_recompute_repository_count_from_db` sets `Repository.rule_count`
    from a live SELECT COUNT(*), not from any counter passed in.
    Guarantees `rule_count` matches what's actually stored even after
    partial-store failures via `_store_rules_safe`'s fallback path."""
    from app.models.repository import Repository

    # Repo row starts with a stale/wrong count of 999.
    db_session.add(_make_repo("sigma", rule_count=999))
    # Only 3 detection rows actually exist.
    for i in range(3):
        db_session.add(_detection(id_=f"real-{i}"))
    await db_session.commit()

    recomputed = await ingestion_service._recompute_repository_count_from_db("sigma")
    assert recomputed == 3

    repo = (await db_session.execute(
        select(Repository).where(Repository.name == "sigma")
    )).scalar_one()
    assert repo.rule_count == 3


@pytest.mark.asyncio
async def test_recompute_count_ignores_other_sources(
    ingestion_service, db_session
):
    """The COUNT filter is per-source; other sources' rows are excluded."""
    db_session.add(_make_repo("sigma", rule_count=0))
    db_session.add(_detection(id_="sigma-1", source="sigma"))
    db_session.add(_detection(id_="elastic-1", source="elastic"))
    db_session.add(_detection(id_="elastic-2", source="elastic"))
    await db_session.commit()

    assert await ingestion_service._recompute_repository_count_from_db("sigma") == 1


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
