"""DX-14 / #156: ingest hashes the normalized logic and stamps when it
moved, so trending can tell a logic change from a metadata edit."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.services.ingestion import IngestionService, logic_fingerprint
from app.utils.datetime_utils import utcnow


def test_fingerprint_ignores_whitespace_only_differences():
    assert logic_fingerprint("a: 1\n  b: 2") == logic_fingerprint("a: 1   b: 2\n")
    assert logic_fingerprint("a: 1") != logic_fingerprint("a: 2")
    assert logic_fingerprint("") is None and logic_fingerprint(None) is None
    assert len(logic_fingerprint("x")) == 40


def _row(logic: str) -> Detection:
    now = utcnow()
    return Detection(
        id="sigma:h", source="sigma", source_file="r.yml", source_repo_url="https://x", title="H",
        detection_logic=logic, language="sigma", raw_content="raw", severity="high", status="stable",
        logic_hash=logic_fingerprint(logic), created_at=now, updated_at=now,
    )


@pytest.mark.asyncio
async def test_store_stamps_logic_changed_at_only_when_the_hash_moves(db_session):
    svc = IngestionService.__new__(IngestionService)
    svc.db = db_session
    errors: list = []
    stats = SimpleNamespace(add_error=lambda **kw: errors.append(kw))

    async def stored() -> Detection:
        db_session.expire_all()
        return (await db_session.execute(select(Detection).where(Detection.id == "sigma:h"))).scalar_one()

    # First sight: a hash, no change event.
    await svc._store_rules_safe([_row("selection:\n  a: 1")], stats)
    first = await stored()
    assert first.logic_hash and first.logic_changed_at is None
    first_seen = first.created_at

    # Re-indented: same normalized logic, still no event.
    await svc._store_rules_safe([_row("selection:\n    a: 1\n")], stats)
    assert (await stored()).logic_changed_at is None

    # The query changes: stamped.
    await svc._store_rules_safe([_row("selection:\n  a: 2")], stats)
    changed = await stored()
    assert changed.logic_changed_at is not None
    stamp = changed.logic_changed_at
    assert changed.created_at == first_seen  # first-seen still carried across merges

    # Metadata-only edit afterwards: the stamp is carried, not reset.
    await svc._store_rules_safe([_row("selection:\n  a:   2")], stats)
    assert (await stored()).logic_changed_at == stamp
    assert errors == []
