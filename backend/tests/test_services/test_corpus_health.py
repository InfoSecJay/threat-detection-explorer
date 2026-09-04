"""Corpus-health report (#124 / teardown F2)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.services.corpus_health import HEALTH_FIELDS, build_report, classify, current_counts, to_csv


def _rule(i: int, source: str = "sigma", **kw) -> Detection:
    base = dict(
        id=f"{source}-{i}", source=source, source_file=f"{i}.yml", source_repo_url="https://x",
        title=f"Rule {i}", detection_logic="x", language="sigma", raw_content="x",
        severity="high", status="stable", platforms=["windows"], data_sources=["sysmon"],
        event_types=["process_creation"], mitre_techniques=["T1059"],
        references=["https://example.test/r"], false_positives=["Admin scripts on build hosts"],
        description="Looks for x",
    )
    base.update(kw)
    return Detection(**base)


def test_classify_flags_each_gap_literally():
    assert classify(["T1059"], ["u"], ["Admin activity"], "d") == set()
    assert classify([], [], [], "") == {"no_attack", "no_references", "no_false_positives", "no_description"}
    assert classify(None, None, None, None) == {"no_attack", "no_references", "no_false_positives", "no_description"}
    # Placeholders count separately from empty, and only when EVERY entry is stock.
    assert classify(["T1"], ["u"], ["Unknown"], "d") == {"placeholder_false_positives"}
    assert classify(["T1"], ["u"], ["unlikely.", "N/A"], "d") == {"placeholder_false_positives"}
    assert classify(["T1"], ["u"], ["Unknown", "Backup software"], "d") == set()
    assert classify(["T1"], ["u"], ["Admin"], "   ") == {"no_description"}


@pytest.mark.asyncio
async def test_current_counts_per_source(db_session):
    db_session.add_all([
        _rule(1),
        _rule(2, mitre_techniques=[], references=[]),
        _rule(3, source="splunk", false_positives=["unknown"], description=None),
        _rule(4, source="splunk", false_positives=[]),
    ])
    await db_session.commit()
    c = await current_counts(db_session)
    assert c["sigma"] == {"_total": 2, "no_attack": 1, "no_references": 1}
    assert c["splunk"] == {"_total": 2, "placeholder_false_positives": 1, "no_description": 1, "no_false_positives": 1}


@pytest.mark.asyncio
async def test_report_totals_percentages_and_csv(db_session):
    db_session.add_all([
        _rule(1), _rule(2, mitre_techniques=[]),
        _rule(3, source="splunk", mitre_techniques=[]), _rule(4, source="splunk"),
    ])
    await db_session.commit()
    r = await build_report(db_session)
    assert r["fields"] == list(HEALTH_FIELDS)
    assert r["total_rules"] == 4 and r["totals"]["no_attack"] == 2 and r["totals_pct"]["no_attack"] == 50.0
    assert [s["source"] for s in r["sources"]] == ["sigma", "splunk"]
    assert r["sources"][0]["pct"]["no_attack"] == 50.0
    assert set(r["field_meta"]) == set(HEALTH_FIELDS)
    assert r["corpus"]["rules"] == 4

    csv_text = to_csv(r)
    lines = csv_text.splitlines()
    assert lines[0].startswith("source,total_rules,no_attack,")
    assert lines[1].startswith("sigma,2,1,") and any(line.startswith("TOTAL,4,2,") for line in lines)
    assert "source_url,https://detectionexplorer.io/methodology/corpus-health" in csv_text


@pytest.mark.asyncio
async def test_routes_serve_json_and_csv(db_session):
    db_session.add_all([_rule(1, references=[]), _rule(2)])
    await db_session.commit()

    async def override():
        yield db_session

    app.dependency_overrides[get_db] = override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            j = await c.get("/api/v1/methodology/corpus-health")
            assert j.status_code == 200
            body = j.json()
            assert body["totals"]["no_references"] == 1 and body["total_rules"] == 2
            assert j.headers["cache-control"].startswith("public, s-maxage=900")

            x = await c.get("/api/v1/methodology/corpus-health.csv")
            assert x.status_code == 200
            assert x.headers["content-type"].startswith("text/csv")
            assert "attachment; filename=\"detection-explorer-corpus-health-" in x.headers["content-disposition"]
            assert x.text.splitlines()[0].startswith("source,total_rules,")
    finally:
        app.dependency_overrides.pop(get_db, None)
