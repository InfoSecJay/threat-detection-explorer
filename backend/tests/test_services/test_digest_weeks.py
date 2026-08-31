"""Permanent weekly digest windows (#91 / teardown F16)."""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.digest import compute_digest, iso_week_label, parse_iso_week


def _rule(i, created, modified=None, source="sigma"):
    return Detection(
        id=f"r{i}", source=source, source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i} title here", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", rule_created_date=created,
        rule_modified_date=modified or created,
    )


class TestWeekParsing:
    def test_monday_to_monday_utc(self):
        start, end = parse_iso_week("2026-w35")
        assert start == datetime(2026, 8, 24)  # naive UTC, matching utcnow()
        assert end == datetime(2026, 8, 31)
        assert start.isoweekday() == 1

    def test_case_and_padding_tolerant(self):
        assert parse_iso_week("2026-W05") == parse_iso_week("2026-w5")

    @pytest.mark.parametrize("bad", ["2026w35", "w35", "2026-w54", "2026-w0", "nope", "2099-w01"])
    def test_bad_weeks_raise(self, bad):
        with pytest.raises(ValueError):
            parse_iso_week(bad)

    def test_label_round_trips(self):
        start, _ = parse_iso_week("2026-w35")
        assert iso_week_label(start) == "2026-w35"


@pytest.mark.asyncio
async def test_week_digest_is_bounded_both_sides(db_session, monkeypatch):
    from app.services.mitre import mitre_service

    monkeypatch.setattr(mitre_service, "get_technique", lambda tid: {})
    monkeypatch.setattr(mitre_service, "get_tactic", lambda tid: {})

    inside = datetime(2026, 8, 26, 12)   # in w35
    before = datetime(2026, 8, 20, 12)   # w34
    after = datetime(2026, 8, 31, 0, 30)  # w36 (past `end`)
    db_session.add_all([
        _rule(1, inside),
        _rule(2, before),
        _rule(3, after),
        _rule(4, before, modified=inside),  # modified inside the week
    ])
    await db_session.commit()

    d = await compute_digest(db_session, week="2026-w35")
    assert d["period"]["week"] == "2026-w35"
    assert d["summary"]["created"] == 1
    assert [r["id"] for r in d["new_rules"]] == ["r1"]
    assert d["summary"]["modified"] == 1
    assert [r["id"] for r in d["modified_rules"]] == ["r4"]


@pytest.mark.asyncio
async def test_week_route_and_400s(db_session):
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        ok = await c.get("/api/digest/week/2026-w35")
        assert ok.status_code == 200
        assert ok.json()["period"]["week"] == "2026-w35"
        assert (await c.get("/api/digest/week/garbage")).status_code == 400
        assert (await c.get("/api/digest/week/2099-w01")).status_code == 400
    app.dependency_overrides.pop(get_db, None)
