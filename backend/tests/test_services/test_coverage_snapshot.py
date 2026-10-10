"""Tests for MITRE coverage snapshots + the newly-covered diff (#9)."""

from datetime import date, datetime, timedelta

import pytest

from app.models.coverage_snapshot import MitreCoverageSnapshot
from app.models.detection import Detection
from app.services.coverage_snapshot import (
    compute_newly_covered,
    write_coverage_snapshot,
)
from app.utils.datetime_utils import utcnow


def _rule(rid: str, source: str, techniques: list[str], created: datetime | None = None):
    return Detection(
        id=rid,
        source=source,
        source_file=f"{rid}.yml",
        source_repo_url="https://example.com/repo.git",
        title=rid,
        detection_logic="x",
        raw_content="x",
        language="sigma",
        mitre_techniques=techniques,
        rule_created_date=created,
    )


@pytest.mark.asyncio
async def test_write_snapshot_counts_and_is_rerun_safe(db_session):
    db_session.add_all([
        _rule("r1", "sigma", ["T1059", "T1027"]),
        _rule("r2", "sigma", ["T1059"]),
        _rule("r3", "splunk", ["T1059"]),
    ])
    await db_session.commit()

    n = await write_coverage_snapshot(db_session)
    assert n == 3  # (T1059,sigma) (T1027,sigma) (T1059,splunk)

    rows = (await db_session.execute(
        MitreCoverageSnapshot.__table__.select()
    )).all()
    counts = {(r.technique_id, r.source): r.rule_count for r in rows}
    assert counts[("T1059", "sigma")] == 2
    assert counts[("T1059", "splunk")] == 1

    # Re-running the same day replaces, not duplicates.
    n2 = await write_coverage_snapshot(db_session)
    assert n2 == 3
    total = len((await db_session.execute(
        MitreCoverageSnapshot.__table__.select()
    )).all())
    assert total == 3


@pytest.mark.asyncio
async def test_snapshot_diff_flags_catalog_and_source_news(db_session):
    today = utcnow().date()
    baseline_day = today - timedelta(days=40)
    # Baseline 40 days ago: sigma covered T1059; nothing covered T1651.
    db_session.add_all([
        MitreCoverageSnapshot(
            snapshot_date=baseline_day, technique_id="T1059",
            source="sigma", rule_count=2,
        ),
        MitreCoverageSnapshot(
            snapshot_date=baseline_day, technique_id="T1027",
            source="splunk", rule_count=1,
        ),
    ])
    # Today: T1651 has its first rule ever (sigma), splunk picked up
    # T1059 (sigma had it), and a brand-new source appeared.
    db_session.add_all([
        _rule("r1", "sigma", ["T1059"]),
        _rule("r2", "sigma", ["T1651"]),
        _rule("r3", "splunk", ["T1059", "T1027"]),
        _rule("r4", "pypanther", ["T1078"]),
    ])
    await db_session.commit()

    got = await compute_newly_covered(db_session, days=30)
    assert got["method"] == "snapshot"
    assert got["baseline_date"] == baseline_day.isoformat()

    catalog_ids = [e["technique_id"] for e in got["catalog_newly_covered"]]
    assert "T1651" in catalog_ids
    assert "T1059" not in catalog_ids  # covered at baseline

    source_news = {
        (e["source"], e["technique_id"]): e
        for e in got["source_newly_covered"]
    }
    assert ("splunk", "T1059") in source_news
    assert source_news[("splunk", "T1059")]["covered_elsewhere"] == ["sigma"]
    # splunk already had T1027 at baseline — not news.
    assert ("splunk", "T1027") not in source_news
    # Onboarded-inside-window source is quarantined, not news.
    assert got["new_sources"] == ["pypanther"]
    assert all(e["source"] != "pypanther" for e in got["source_newly_covered"])
    # T1078 comes only from the new source and nothing had it at
    # baseline — it IS catalog-wide news.
    assert "T1078" in catalog_ids


@pytest.mark.asyncio
async def test_rule_dates_fallback_without_snapshots(db_session):
    now = utcnow()
    old = now - timedelta(days=400)
    recent = now - timedelta(days=5)
    db_session.add_all([
        # T1059: sigma covered it long ago; splunk's first rule is recent.
        _rule("r1", "sigma", ["T1059"], created=old),
        _rule("r2", "splunk", ["T1059"], created=recent),
        # T1651: first rule anywhere is recent -> catalog news.
        _rule("r3", "sigma", ["T1651"], created=recent),
        # No creation date -> contributes nothing.
        _rule("r4", "sentinel", ["T1027"], created=None),
    ])
    await db_session.commit()

    got = await compute_newly_covered(db_session, days=30)
    assert got["method"] == "rule_dates"
    assert got["baseline_date"] is None

    catalog_ids = [e["technique_id"] for e in got["catalog_newly_covered"]]
    assert catalog_ids == ["T1651"]

    source_news = {
        (e["source"], e["technique_id"]): e
        for e in got["source_newly_covered"]
    }
    assert ("splunk", "T1059") in source_news
    assert source_news[("splunk", "T1059")]["covered_elsewhere"] == ["sigma"]
    assert ("sigma", "T1059") not in source_news  # old coverage


@pytest.mark.asyncio
async def test_sources_filter_applies_to_source_list(db_session):
    now = utcnow()
    db_session.add_all([
        _rule("r1", "sigma", ["T1059"], created=now - timedelta(days=400)),
        _rule("r2", "splunk", ["T1059"], created=now - timedelta(days=5)),
        _rule("r3", "elastic", ["T1059"], created=now - timedelta(days=5)),
    ])
    await db_session.commit()

    got = await compute_newly_covered(db_session, days=30, sources=["splunk"])
    assert all(e["source"] == "splunk" for e in got["source_newly_covered"])


# -- #172: the snapshot counts what counts as coverage --------------------------


def _rule_x(rid: str, source: str, techniques: list[str], **kw):
    r = _rule(rid, source, techniques)
    for k, v in kw.items():
        setattr(r, k, v)
    return r


@pytest.mark.asyncio
async def test_snapshot_applies_the_coverage_rule(db_session):
    """Hunting, passthrough, deprecated and a linked PyPanther port do not
    count (DX-05 / #166); an unlinked pypanther rule and a plain rule do."""
    db_session.add_all([
        _rule("r1", "sigma", ["T1059"]),
        _rule_x("h1", "elastic", ["T1059"], rule_modality="hunting"),
        _rule_x("p1", "sentinel", ["T1059"], rule_modality="passthrough"),
        _rule_x("d1", "splunk", ["T1059"], status="deprecated"),
        _rule_x("pa", "panther", ["T1078"], rule_id="AWS.X"),
        _rule_x("py", "pypanther", ["T1078"], rule_id="AWS.X-prototype", duplicate_of="pa"),
        _rule_x("py2", "pypanther", ["T1110"], rule_id="AWS.Solo-prototype"),
    ])
    await db_session.commit()
    n = await write_coverage_snapshot(db_session)
    rows = (await db_session.execute(MitreCoverageSnapshot.__table__.select())).all()
    counts = {(r.technique_id, r.source): r.rule_count for r in rows}
    assert counts == {("T1059", "sigma"): 1, ("T1078", "panther"): 1, ("T1110", "pypanther"): 1}
    assert n == 3


@pytest.mark.asyncio
async def test_pre_switch_baseline_falls_back_to_rule_dates(db_session, monkeypatch):
    """A baseline snapshot older than STRICT_SNAPSHOT_SINCE is not
    comparable: the diff uses the git-derived path and says so, and that
    path applies the coverage rule too."""
    from app.services import coverage_snapshot

    today = utcnow().date()
    monkeypatch.setattr(coverage_snapshot, "STRICT_SNAPSHOT_SINCE", today - timedelta(days=10))
    db_session.add(MitreCoverageSnapshot(
        snapshot_date=today - timedelta(days=40), technique_id="T1059", source="sigma", rule_count=2,
    ))
    recent = utcnow() - timedelta(days=5)
    db_session.add_all([
        _rule("r1", "sigma", ["T1059"], created=utcnow() - timedelta(days=400)),
        _rule("r2", "sigma", ["T1651"], created=recent),
        _rule_x("h1", "elastic", ["T1027"], created=recent, rule_modality="hunting"),
    ])
    await db_session.commit()

    got = await compute_newly_covered(db_session, days=30)
    assert got["method"] == "rule_dates" and got["baseline_date"] is None
    ids = [e["technique_id"] for e in got["catalog_newly_covered"]]
    assert ids == ["T1651"], "the hunting-only technique is not newly covered"

    # With the cut-off before the baseline, the exact snapshot diff is back.
    monkeypatch.setattr(coverage_snapshot, "STRICT_SNAPSHOT_SINCE", today - timedelta(days=50))
    got = await compute_newly_covered(db_session, days=30)
    assert got["method"] == "snapshot"
