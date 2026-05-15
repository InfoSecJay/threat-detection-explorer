"""Integration tests for the search service.

Strategy: spin up an in-memory SQLite (via the shared `db_session`
fixture), insert a small fixture corpus that exercises every filter
dimension, then execute real searches and assert on the result set.
This catches three bug classes that pure-mock testing misses:

  1. SQLAlchemy expression composition bugs — the JSON-array `ilike`
     trick relies on a quoted match (``%"value"%``) to avoid substring
     false-positives. A regression that drops the quotes would silently
     match more rules than intended.
  2. Filter conjunction semantics — within a dimension we OR, across
     dimensions we AND. Easy to flip by accident.
  3. Pagination + total-count drift — the count query and the data
     query must apply the same filters; in older versions they didn't.

The fixtures lean small (~10 rows) so failures point straight at a
concrete rule rather than a sea of data.
"""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.search import SearchFilters, SearchService


# ── Fixture corpus ──────────────────────────────────────────────────────


def _make(  # noqa: PLR0913 — many optional kwargs is the point
    *,
    id_: str,
    source: str,
    title: str,
    severity: str = "medium",
    status: str = "stable",
    language: str = "sigma",
    description: str = "",
    detection_logic: str = "",
    raw_content: str = "",
    mitre_tactics: list | None = None,
    mitre_techniques: list | None = None,
    tags: list | None = None,
    platforms: list | None = None,
    event_types: list | None = None,
    data_sources: list | None = None,
    extracted_event_ids: list | None = None,
    extracted_process_names: list | None = None,
    extracted_api_actions: list | None = None,
    query_complexity: str = "moderate",
) -> Detection:
    """Build a Detection row with sensible defaults for everything we
    don't care about in a given test."""
    return Detection(
        id=id_,
        source=source,
        source_file=f"{source}/{id_}.yml",
        source_repo_url=f"https://example.test/{source}",
        title=title,
        description=description,
        severity=severity,
        status=status,
        language=language,
        detection_logic=detection_logic or "placeholder",
        raw_content=raw_content or "placeholder",
        mitre_tactics=mitre_tactics or [],
        mitre_techniques=mitre_techniques or [],
        tags=tags or [],
        platforms=platforms or [],
        event_types=event_types or [],
        data_sources=data_sources or [],
        extracted_event_ids=extracted_event_ids or [],
        extracted_process_names=extracted_process_names or [],
        extracted_api_actions=extracted_api_actions or [],
        query_complexity=query_complexity,
    )


@pytest.fixture
def corpus() -> list[Detection]:
    """A 9-rule corpus that covers every filter dimension at least twice."""
    return [
        _make(id_="r1", source="sigma",   title="Suspicious PowerShell",
              severity="high", status="stable", language="sigma",
              description="Detects encoded commands",
              raw_content="powershell -enc",
              mitre_tactics=["TA0002"], mitre_techniques=["T1059.001"],
              platforms=["windows"], event_types=["process"],
              extracted_event_ids=["4688"], extracted_process_names=["powershell.exe"],
              tags=["attack.execution"], query_complexity="moderate"),
        _make(id_="r2", source="sigma",   title="Linux SSH brute force",
              severity="critical", status="stable", language="sigma",
              description="Auth failures",
              raw_content="ssh failed",
              mitre_tactics=["TA0006"], mitre_techniques=["T1110"],
              platforms=["linux"], event_types=["authentication"],
              tags=["attack.credential_access"], query_complexity="simple"),
        _make(id_="r3", source="splunk",  title="O365 mailbox export",
              severity="high", status="experimental", language="spl",
              description="Detects bulk mailbox exports",
              raw_content="| tstats from o365",
              mitre_tactics=["TA0009"], mitre_techniques=["T1114.002"],
              platforms=["o365"], event_types=["audit_event"],
              extracted_api_actions=["New-MailboxExportRequest"],
              tags=["analytic_story:o365_bulk_export"], query_complexity="complex"),
        _make(id_="r4", source="elastic", title="AWS root login",
              severity="critical", status="stable", language="kuery",
              description="Root account console activity",
              raw_content="ConsoleLogin root",
              mitre_tactics=["TA0001"], mitre_techniques=["T1078.004"],
              platforms=["aws"], event_types=["authentication"],
              extracted_api_actions=["ConsoleLogin"], query_complexity="simple"),
        _make(id_="r5", source="sublime", title="Phishing: QakBot delivery",
              severity="high", status="stable", language="mql",
              description="QakBot malware delivered via attachment",
              raw_content="malfam qakbot",
              tags=["Malfam: QakBot"], query_complexity="moderate"),
        _make(id_="r6", source="sentinel", title="Solorigate beacon",
              severity="critical", status="stable", language="kql",
              description="NOBELIUM C2 indicators",
              raw_content="solorigate dns",
              tags=["Solorigate", "NOBELIUM"],
              platforms=["windows"], event_types=["network"]),
        _make(id_="r7", source="sigma",   title="Deprecated indicator",
              severity="low", status="deprecated", language="sigma",
              description="Old IOC list",
              raw_content="old"),
        _make(id_="r8", source="elastic", title="Cross-platform process anomaly",
              severity="medium", status="stable", language="eql",
              raw_content="process anomaly",
              platforms=["windows", "linux", "macos"],
              extracted_process_names=["bash", "powershell.exe"]),
        _make(id_="r9", source="splunk",  title="T1059 family — generic",
              severity="medium", status="stable", language="spl",
              raw_content="generic exec",
              # Important: this rule has T1059 but NOT T1059.001 — used to
              # verify the quoted-substring filter doesn't false-positive
              # T1059 onto rules tagged with sub-techniques.
              mitre_techniques=["T1059"]),
    ]


@pytest.fixture
async def search(db_session, corpus):
    """Insert the corpus and return a SearchService bound to the session."""
    db_session.add_all(corpus)
    await db_session.commit()
    return SearchService(db_session)


# ── Helpers ─────────────────────────────────────────────────────────────


def ids(detections: list[Detection]) -> set[str]:
    return {d.id for d in detections}


# ── Source / status / severity / language: exact-match in_() filters ────


@pytest.mark.asyncio
async def test_filter_by_single_source(search):
    rows, total = await search.search_detections(SearchFilters(sources=["sigma"]))
    assert ids(rows) == {"r1", "r2", "r7"}
    assert total == 3


@pytest.mark.asyncio
async def test_filter_by_multiple_sources_unions(search):
    rows, total = await search.search_detections(SearchFilters(sources=["splunk", "elastic"]))
    assert ids(rows) == {"r3", "r4", "r8", "r9"}
    assert total == 4


@pytest.mark.asyncio
async def test_filter_by_status(search):
    rows, _ = await search.search_detections(SearchFilters(statuses=["deprecated"]))
    assert ids(rows) == {"r7"}


@pytest.mark.asyncio
async def test_filter_by_severity(search):
    rows, _ = await search.search_detections(SearchFilters(severities=["critical"]))
    assert ids(rows) == {"r2", "r4", "r6"}


@pytest.mark.asyncio
async def test_filter_by_language(search):
    rows, _ = await search.search_detections(SearchFilters(languages=["spl"]))
    assert ids(rows) == {"r3", "r9"}


# ── Cross-dimension filters AND together ────────────────────────────────


@pytest.mark.asyncio
async def test_source_and_severity_compose_with_and(search):
    rows, _ = await search.search_detections(
        SearchFilters(sources=["sigma"], severities=["critical"])
    )
    assert ids(rows) == {"r2"}


# ── MITRE filters ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_by_mitre_technique_exact_quoting(search):
    """The quoted JSON match (``%"T1059"%``) must NOT false-positive
    onto rules tagged with the sub-technique T1059.001."""
    rows, _ = await search.search_detections(SearchFilters(mitre_techniques=["T1059"]))
    assert ids(rows) == {"r9"}, "T1059 must not match T1059.001 in r1"


@pytest.mark.asyncio
async def test_filter_by_mitre_technique_subtechnique(search):
    rows, _ = await search.search_detections(SearchFilters(mitre_techniques=["T1059.001"]))
    assert ids(rows) == {"r1"}


@pytest.mark.asyncio
async def test_filter_by_mitre_tactic(search):
    rows, _ = await search.search_detections(SearchFilters(mitre_tactics=["TA0001"]))
    assert ids(rows) == {"r4"}


# ── Canonical taxonomy filters ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_by_platform(search):
    rows, _ = await search.search_detections(SearchFilters(platforms=["o365"]))
    assert ids(rows) == {"r3"}


@pytest.mark.asyncio
async def test_filter_by_platform_multi_os_rule(search):
    """A rule tagged [windows, linux, macos] should hit on any of those."""
    rows, _ = await search.search_detections(SearchFilters(platforms=["macos"]))
    assert ids(rows) == {"r8"}


@pytest.mark.asyncio
async def test_filter_by_event_categories_uses_taxonomy_event_types(search):
    """The legacy `event_categories` filter key now matches against
    `event_types` — explicit URL-backwards-compat behavior."""
    rows, _ = await search.search_detections(SearchFilters(event_categories=["authentication"]))
    assert ids(rows) == {"r2", "r4"}


# ── Extracted observable filters ────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_by_event_id(search):
    rows, _ = await search.search_detections(SearchFilters(event_ids=["4688"]))
    assert ids(rows) == {"r1"}


@pytest.mark.asyncio
async def test_filter_by_process_name_unquoted_substring(search):
    """`process_names` filter uses unquoted substring (``%powershell.exe%``).
    Both rules with that process should match."""
    rows, _ = await search.search_detections(SearchFilters(process_names=["powershell.exe"]))
    assert ids(rows) == {"r1", "r8"}


@pytest.mark.asyncio
async def test_filter_by_query_complexity(search):
    rows, _ = await search.search_detections(SearchFilters(query_complexity=["complex"]))
    assert ids(rows) == {"r3"}


@pytest.mark.asyncio
async def test_filter_by_api_action(search):
    rows, _ = await search.search_detections(SearchFilters(api_actions=["ConsoleLogin"]))
    assert ids(rows) == {"r4"}


# ── Text search ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_text_search_matches_title(search):
    rows, _ = await search.search_detections(SearchFilters(search="QakBot"))
    assert "r5" in ids(rows)


@pytest.mark.asyncio
async def test_text_search_matches_description(search):
    rows, _ = await search.search_detections(SearchFilters(search="encoded"))
    assert "r1" in ids(rows)


@pytest.mark.asyncio
async def test_text_search_is_case_insensitive(search):
    rows, _ = await search.search_detections(SearchFilters(search="POWERSHELL"))
    assert "r1" in ids(rows)


# ── Sorting ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sort_by_title_asc(search):
    rows, _ = await search.search_detections(
        SearchFilters(sources=["sigma"], sort_by="title", sort_order="asc")
    )
    titles = [d.title for d in rows]
    assert titles == sorted(titles)


@pytest.mark.asyncio
async def test_sort_by_title_desc(search):
    rows, _ = await search.search_detections(
        SearchFilters(sources=["sigma"], sort_by="title", sort_order="desc")
    )
    titles = [d.title for d in rows]
    assert titles == sorted(titles, reverse=True)


@pytest.mark.asyncio
async def test_unknown_sort_field_falls_back_to_title(search):
    rows, _ = await search.search_detections(
        SearchFilters(sources=["sigma"], sort_by="not_a_real_column", sort_order="asc")
    )
    assert [d.title for d in rows] == sorted(d.title for d in rows)


# ── Pagination + total drift ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_total_count_matches_filter(search):
    """Total reflects the filtered set, not the entire table — guards
    against an old bug where the count query forgot the filters."""
    _, total = await search.search_detections(SearchFilters(severities=["critical"]))
    assert total == 3


@pytest.mark.asyncio
async def test_pagination_offset_and_limit(search):
    rows_page1, total = await search.search_detections(
        SearchFilters(sources=["sigma"], offset=0, limit=2, sort_by="title", sort_order="asc")
    )
    rows_page2, _ = await search.search_detections(
        SearchFilters(sources=["sigma"], offset=2, limit=2, sort_by="title", sort_order="asc")
    )
    assert len(rows_page1) == 2
    assert len(rows_page2) == 1
    assert total == 3
    assert ids(rows_page1).isdisjoint(ids(rows_page2))


# ── Default behaviour ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_filters_returns_everything(search, corpus):
    rows, total = await search.search_detections(SearchFilters())
    assert total == len(corpus)


@pytest.mark.asyncio
async def test_empty_string_search_is_treated_as_no_search(search, corpus):
    """A literal empty `search` string should not collapse the result
    set to zero — it should behave like no text filter at all."""
    rows, total = await search.search_detections(SearchFilters(search=""))
    assert total == len(corpus)
