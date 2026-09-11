"""ATT&CK coverage by domain (#135): the row filter feeding the matrix."""

from __future__ import annotations

import pytest

from app.api.routes.compare import coverage_rows
from app.models.detection import Detection


def _rule(id_: str, source: str, domains: list[str], techniques: list[str]) -> Detection:
    return Detection(
        id=id_, source=source, source_file=f"{id_}.yml", source_repo_url="https://x",
        title=id_, detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", mitre_techniques=techniques, domains=domains,
    )


@pytest.mark.asyncio
async def test_domain_filter_selects_rules_carrying_that_domain(db_session):
    db_session.add_all([
        _rule("a", "sigma", ["endpoint"], ["T1059"]),
        _rule("b", "panther", ["identity"], ["T1078"]),
        _rule("c", "elastic", ["cloud", "identity"], ["T1078.004"]),
        _rule("d", "sigma", ["unknown"], ["T1190"]),
    ])
    await db_session.commit()

    everything = await coverage_rows(db_session)
    assert sorted(s for s, _ in everything) == ["elastic", "panther", "sigma", "sigma"]

    identity = await coverage_rows(db_session, "identity")
    assert sorted(t for _, ts in identity for t in ts) == ["T1078", "T1078.004"]

    assert [ts for _, ts in await coverage_rows(db_session, "unknown")] == [["T1190"]]
    assert await coverage_rows(db_session, "email") == []


@pytest.mark.asyncio
async def test_coverage_rows_skip_rules_that_are_not_coverage(db_session):
    """DX-05 / #147: a hunting query, a building block, a forwarded alert,
    an indicator list and a deprecated rule all carry technique tags;
    none of them is a detection of that technique."""
    def tagged(id_, **kw):
        d = _rule(id_, "sentinel", ["endpoint"], ["T1055"])
        for k, v in kw.items():
            setattr(d, k, v)
        return d

    db_session.add_all([
        tagged("plain"),
        tagged("hunt", rule_modality="hunting"),
        tagged("bb", rule_modality="building_block"),
        tagged("pass", rule_modality="passthrough"),
        tagged("ioc", rule_modality="indicator_match"),
        tagged("old", status="deprecated"),
        tagged("corr", rule_modality="correlation"),  # alert-on-alert still counts
    ])
    await db_session.commit()
    rows = await coverage_rows(db_session)
    assert len(rows) == 2  # plain + corr
    assert all(ts == ["T1055"] for _, ts in rows)
