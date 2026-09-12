"""'Before you deploy' prerequisites (DX-16 / #158): Sigma
logsource.definition, Elastic setup / integrations / min stack version
and Splunk how_to_implement reach the API as `deploy_notes`."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.detection import Detection
from app.normalizers.elastic import _deploy_notes, _guide_text
from app.normalizers.sigma import SigmaNormalizer
from app.normalizers.splunk import SplunkNormalizer
from app.parsers.base import ParsedRule
from app.parsers.sigma import SigmaParser

DEFINITION_LINE = (
    "    definition: 'Enable the builtin Zeek script that logs all HTTP header names "
    "by adding @load policy/protocols/http/header-names to local.zeek'\n"
)
SIGMA_ZEEK = f"""title: OMIGOD HTTP No Authentication RCE
id: 3cfc23e0-7022-51ac-8e05-04cb43afff19
status: test
description: Detects the OMIGOD exploit.
logsource:
    category: proxy
    product: zeek
    service: http
{DEFINITION_LINE}detection:
    selection:
        client_header_names|contains: 'AUTHORIZATION'
    condition: selection
level: high
"""


def test_sigma_logsource_definition_becomes_deploy_notes():
    parsed = SigmaParser().parse(Path("rules/network/zeek/zeek_http_omigod.yml"), SIGMA_ZEEK)
    assert parsed is not None
    assert parsed.extra["logsource_definition"].startswith("Enable the builtin Zeek script")
    # The resolver's log_source keys are untouched by the new field.
    assert set(parsed.log_source) == {"product", "category", "service"}
    n = SigmaNormalizer("https://github.com/SigmaHQ/sigma").normalize(parsed)
    assert n.deploy_notes is not None and "@load policy/protocols/http/header-names" in n.deploy_notes


def test_sigma_without_a_definition_says_nothing():
    parsed = SigmaParser().parse(Path("rules/x.yml"), SIGMA_ZEEK.replace(DEFINITION_LINE, ""))
    assert parsed is not None and parsed.extra["logsource_definition"] is None
    assert SigmaNormalizer("https://github.com/SigmaHQ/sigma").normalize(parsed).deploy_notes is None


def test_elastic_deploy_notes_lists_integrations_and_min_version_then_setup():
    assert _deploy_notes("Install the Zeek integration.", ["network_traffic", "zeek"], "8.12.0") == (
        "Integrations: network_traffic, zeek\nMinimum stack version: 8.12.0\n\nInstall the Zeek integration."
    )
    assert _deploy_notes("  ", ["okta"], None) == "Integrations: okta"
    assert _deploy_notes(None, [], None) is None
    assert _deploy_notes(None, [None, " "], "") is None


def test_elastic_guide_no_longer_carries_setup():
    assert _guide_text("## Triage\n\nCheck the user.") == "## Triage\n\nCheck the user."
    assert _guide_text(" ") is None and _guide_text(None) is None


def test_splunk_how_to_implement_becomes_deploy_notes():
    parsed = ParsedRule(
        source="splunk", file_path="detections/endpoint/x.yml", raw_content="raw", title="X",
        detection_logic_raw={
            "search": "| tstats count from datamodel=Endpoint.Processes",
            "how_to_implement": "  Requires Sysmon or the Endpoint datamodel.  ",
        },
        description="d", author="a", status="production", severity="high",
        log_source={"product": "endpoint"}, tags=[], mitre_attack={"tactics": [], "techniques": []},
        false_positives=[],
        extra={"id": "x", "type": "TTP", "data_source": [], "security_domain": "endpoint",
               "analytic_stories": [], "references": [], "date": "2024-03-15", "cve": [], "rba": {}},
    )
    n = SplunkNormalizer("https://github.com/splunk/security_content").normalize(parsed)
    assert n.deploy_notes == "Requires Sysmon or the Endpoint datamodel."


@pytest.mark.asyncio
async def test_detail_response_carries_deploy_notes_and_never_a_literal_bracket_pair(db_session):
    common = dict(source="sigma", source_repo_url="https://x", detection_logic="x", language="sigma",
                  raw_content="raw", severity="high", status="stable")
    db_session.add(Detection(id="sigma:zeek", source_file="a.yml", title="Zeek", deploy_notes="Enable X.", **common))
    # The column migration used to backfill new Text columns with the
    # JSON default '[]'; a row from that window must read as no notes.
    db_session.add(Detection(id="sigma:bracket", source_file="b.yml", title="Bracket", deploy_notes="[]", **common))
    db_session.add(Detection(id="sigma:none", source_file="c.yml", title="None", **common))
    await db_session.commit()

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            zeek = (await c.get("/api/detections/sigma:zeek")).json()
            bracket = (await c.get("/api/detections/sigma:bracket")).json()
            none = (await c.get("/api/detections/sigma:none")).json()
            bot = await c.get("/api/prerender/detection/sigma:zeek", headers={"user-agent": "Googlebot"})
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert zeek["deploy_notes"] == "Enable X."
    assert bracket["deploy_notes"] is None and none["deploy_notes"] is None
    assert bot.status_code == 200 and "Before you deploy" in bot.text and "Enable X." in bot.text
