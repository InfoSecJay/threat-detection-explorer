"""End-to-end ingestion smoke tests — one rule per source through the
full parse → normalize → extract → store pipeline.

The per-layer tests (parsers, normalizers, search, etc.) pin each
component in isolation. These tests pin the WIRING between them.
The two regressions we caught earlier this week — Splunk normalizer
dropping the ``story:`` prefix, parser substring-exclude breaking
``test.toml`` — would both have failed an e2e smoke first, before
shipping. This file is that safety net.

Strategy:
  - One short raw-content fixture per source (real-format YAML/TOML).
  - A small ``ingest_one()`` helper that drives parse → normalize →
    _to_detection_model → ``db.add()`` + commit, then reads the row
    back. Mirrors the production ``IngestionService`` inner loop
    minus the file-discovery / batching.
  - One test per source. Assertions are intentionally TARGETED at
    cross-layer wiring — the canonical taxonomy resolved from raw
    vendor metadata, MITRE pass-through, key extracted observables,
    `source_rule_url` constructed correctly. NOT exhaustive — that's
    what the per-layer tests are for.

If a future refactor breaks the wiring (e.g. a normalizer stops
calling ``_resolve_taxonomy``, or the ingestion service stops
copying a column from ``NormalizedDetection`` to ``Detection``),
the failing assertion will name the source and the broken field.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.detection import Detection
from app.normalizers import (
    Auth0Normalizer,
    ElasticHuntingNormalizer,
    ElasticNormalizer,
    ElasticProtectionsNormalizer,
    GoogleSecOpsNormalizer,
    LOLRMMNormalizer,
    OktaNormalizer,
    PantherNormalizer,
    SentinelNormalizer,
    SigmaNormalizer,
    SplunkNormalizer,
    SublimeNormalizer,
)
from app.parsers import (
    Auth0Parser,
    ElasticHuntingParser,
    ElasticParser,
    ElasticProtectionsParser,
    GoogleSecOpsParser,
    OktaParser,
    LOLRMMParser,
    PantherParser,
    SentinelParser,
    SigmaParser,
    SplunkParser,
    SublimeParser,
)
from app.services.ingestion import IngestionService

from tests.conftest import (
    SAMPLE_ELASTIC_RULE,
    SAMPLE_SIGMA_RULE,
    SAMPLE_SPLUNK_RULE,
)


# ── Sample raw rules for the 5 sources missing from conftest.py ──────


SAMPLE_SUBLIME_RULE = """\
name: "Phishing attachment from QakBot delivery campaign"
description: |
  Detects QakBot delivery via container attachments (zip / iso / img).
type: "rule"
severity: "high"
authors:
  - name: "Sublime Security"
source: |
  any(attachments,
      .file_extension in~ ["zip", "iso", "img"]
      and length(attachments) >= 1)
tags:
  - "Attack surface reduction"
  - "Malfam: QakBot"
attack_types:
  - "Malware/Ransomware"
references:
  - "https://abuse.ch/url/qakbot"
"""


SAMPLE_SENTINEL_RULE = """\
id: 12345678-aaaa-bbbb-cccc-1234567890ab
name: Mail Forwarding Configured to External Address
description: |
  Detects mailbox forwarding configuration to external SMTP addresses
  via Office 365 audit log.
severity: Medium
status: Available
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Collection
relevantTechniques:
  - T1114.003
query: |
  OfficeActivity
  | where OfficeWorkload == "Exchange"
  | where Operation == "Set-Mailbox"
  | where Parameters has "ForwardingSmtpAddress"
kind: Scheduled
version: 1.0.0
tags:
  - NOBELIUM
"""


SAMPLE_ELASTIC_PROTECTIONS_RULE = """\
[rule]
description = "Detects suspicious handle acquisition on LSASS process."
endpoint = {capabilities = ["kill_process"]}
id = "abcd-1234-efgh-5678"
license = "Elastic License v2"
name = "Suspicious LSASS Handle Acquisition"
os_list = ["windows"]
query = '''
process where event.action == "process_handle" and
target.process.name == "lsass.exe"
'''
version = "1.0.1"

# Elastic Protections puts the MITRE block at the top level of the
# TOML (NOT nested under [rule]). The parser's _extract_mitre walks
# `data["threat"]` directly.
[[threat]]
framework = "MITRE ATT&CK"

[[threat.technique]]
id = "T1003"
name = "OS Credential Dumping"

[[threat.technique.subtechnique]]
id = "T1003.001"
name = "LSASS Memory"

[threat.tactic]
id = "TA0006"
name = "Credential Access"

[[actions]]
type = "alert"
"""


SAMPLE_ELASTIC_HUNTING_RULE = '''\
[hunt]
author = "Elastic"
description = "Hunts for IAM user creation by unexpected principals."
integration = ["aws.cloudtrail"]
uuid = "hunt-uuid-12345"
name = "AWS IAM User Created Outside Allowed Roles"
language = ["ES|QL"]
license = "Elastic License v2"
mitre = ["T1136.003"]
query = [
    """
    FROM logs-aws.cloudtrail-*
    | WHERE event.action == "CreateUser"
    | STATS count = COUNT(*) BY user.name
    """,
]
notes = ["Tune by trusted-principal allowlist."]
'''


SAMPLE_PANTHER_RULE_YML = """\
AnalysisType: rule
RuleID: AWS.CloudTrail.Stopped
Filename: aws_cloudtrail_stopped.py
DisplayName: CloudTrail Was Stopped
Enabled: true
LogTypes:
  - AWS.CloudTrail
Severity: High
CreateAlert: true
DedupPeriodMinutes: 60
Threshold: 1
Description: Detects StopLogging API calls that turn off CloudTrail.
Reference: https://example.com/mitre-t1562-008
Runbook: Investigate the actor.
Tags:
  - Defense Evasion:Impair Defenses
Reports:
  MITRE ATT&CK:
    - TA0005:T1562.008
  CIS:
    - 3.5
"""

SAMPLE_PANTHER_RULE_PY = """\
def rule(event):
    return event.get("eventName") == "StopLogging"
"""


SAMPLE_AUTH0_RULE = """\
title: Refresh Token Reuse Detection
id: a7b2e75c-7171-11f0-aa28-723487b9527c
status: experimental
description: |
    Detects when a refresh token is reused.
author: Okta
date: 2025-07-11
modified: 2025-09-02
logsource:
    product: auth0
detection:
    selection:
        data.type: ferrt
        data.description: "Unsuccessful Refresh Token exchange, reused refresh token detected"
    condition: selection
splunk: |
    index=auth0 data.type=ferrt
tenant_logs: |
    type: "ferrt"
prevention:
    - Ensure correct refresh token usage.
falsepositives:
    - Misconfigured applications caching refresh tokens.
level: medium
tags:
    - attack.credential-access
    - attack.persistence
    - attack.t1550.001
    - attack.t1078
"""


SAMPLE_OKTA_RULE = """\
title: Access to Admin Console with Weak MFA Factor
id: 65ca8dcc6f50976012b74700e6067ba6
description: |
  Detects when a user accesses the Okta Admin Console with a weak MFA factor.
references:
  - https://help.okta.com/en-us/content/topics/security/mfa/mfa-enable-admins.htm
author:
  - Datadog
  - Okta
created_date: "2025-01-06"
modified_date: "2025-01-06"
threat:
  Tactic:
    - Initial Access
  Technique:
    - T1078: Valid Accounts
prevention:
  - Configure an Admin App Policy to enable MFA for the Okta Admin Console.
detection:
  okta_systemlog:
    OIE: |
      eventType eq "user.authentication.verify" and outcome.result eq "SUCCESS"
    datadog: |
      source:okta @evt.name:user.authentication.verify @evt.outcome:SUCCESS
false_positives:
  - Legitimate administrative users require a break glass solution.
"""


SAMPLE_GOOGLE_SECOPS_RULE = """\
rule aws_console_login_without_mfa {

    meta:
      author = "Google Cloud Security"
      description = "Detect when a user logs into AWS console without MFA."
      rule_id = "mr_b03d1e57-7ed0-49e7-b125-6c18b364ae8c"
      rule_name = "AWS Console Login Without MFA"
      mitre_attack_tactic = "Initial Access"
      mitre_attack_technique = "Valid Accounts: Cloud Accounts"
      mitre_attack_url = "https://attack.mitre.org/techniques/T1078/004/"
      mitre_attack_version = "v13.1"
      type = "Alert"
      data_source = "AWS CloudTrail"
      platform = "AWS"
      severity = "Low"
      priority = "Low"

    events:
      $login.metadata.vendor_name = "AMAZON"
      $login.metadata.event_type = "USER_LOGIN"
      $login.extensions.auth.auth_details = "MFAUsed: No"

    match:
      $account_id over 1h

    outcome:
      $risk_score = max(35)

    condition:
      $login
}
"""


SAMPLE_LOLRMM_RULE = """\
title: AnyDesk Remote Access Tool Execution
id: lolrmm-anydesk-001
status: stable
description: Detects AnyDesk RMM tool execution by image name.
author: LOLRMM Project
date: 2023/06/01
modified: 2024/02/14
references:
  - https://anydesk.com
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\anydesk.exe'
  condition: selection
falsepositives:
  - Authorized remote IT support
level: medium
tags:
  - lolrmm
  - attack.command_and_control
  - attack.t1219
"""


# ── Helper ──────────────────────────────────────────────────────────


async def ingest_one(
    parser, normalizer, file_path: str, content: str, db_session
) -> Detection:
    """Run one rule through parse → normalize → store, return the row.

    Mirrors the production ``IngestionService.ingest_repository`` inner
    loop minus the file-discovery + batching. Bypasses the service's
    ``__init__`` because that eagerly builds 8 parsers + 8 normalizers,
    each of which expects on-disk repo paths to exist.
    """
    fp = Path(file_path)
    assert parser.can_parse(fp), f"can_parse rejected {file_path}"

    parsed = parser.parse(fp, content)
    assert parsed is not None, f"parser returned None for {file_path}"

    normalized = normalizer.normalize(parsed)

    svc = IngestionService.__new__(IngestionService)
    detection = svc._to_detection_model(normalized)

    db_session.add(detection)
    await db_session.commit()

    # Read back via the model query path so we exercise the same code
    # users hit through the API rather than just inspecting the staged
    # in-memory object.
    return (
        await db_session.execute(
            select(Detection).where(Detection.id == detection.id)
        )
    ).scalar_one()


# ── Per-source e2e tests ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_e2e_sigma(db_session):
    d = await ingest_one(
        SigmaParser(),
        SigmaNormalizer("https://github.com/SigmaHQ/sigma"),
        "rules/windows/process_creation/proc_creation_susp_powershell.yml",
        SAMPLE_SIGMA_RULE,
        db_session,
    )
    assert d.source == "sigma"
    assert d.title == "Suspicious PowerShell Command Line"
    assert d.language == "sigma"
    assert d.severity == "high"
    # Canonical taxonomy resolved from logsource: windows/process_creation
    assert "windows" in d.platforms
    assert "process_creation" in d.event_types
    # MITRE techniques routed from `attack.t...` tags
    assert "T1059.001" in d.mitre_techniques
    # Embedded date pulled from Sigma `date:` field
    assert d.rule_created_date is not None
    # Source URL deep-links into the right repo + branch
    assert d.source_rule_url is not None
    assert "SigmaHQ/sigma" in d.source_rule_url


@pytest.mark.asyncio
async def test_e2e_elastic(db_session):
    d = await ingest_one(
        ElasticParser(),
        ElasticNormalizer("https://github.com/elastic/detection-rules"),
        "rules/windows/credential_access_susp_powershell.toml",
        SAMPLE_ELASTIC_RULE,
        db_session,
    )
    assert d.source == "elastic"
    assert d.title == "Suspicious PowerShell Execution"
    assert d.language == "kql"  # rule.type=query + kuery default
    assert d.severity == "high"
    assert d.status == "stable"  # production → stable
    # The list-author from TOML gets joined to a string
    assert d.author == "Test Author"
    # Index pattern resolves to a canonical Windows endpoint platform
    assert "windows" in d.platforms
    # MITRE technique pulled from rule.threat[].technique[]
    assert "T1059" in d.mitre_techniques


# Regression: real Elastic AWS rules use multiline triple-quoted
# strings for description / false_positives / setup. The legacy `toml`
# package (PyPI `toml`) chokes on these with `IndexError: string index
# out of range` and silently dropped ~70 production rules at sync time.
# Switched to stdlib `tomllib` (Python 3.11+). This fixture mirrors the
# exact structural shape that broke the old parser.
SAMPLE_ELASTIC_AWS_MULTILINE_RULE = '''\
[metadata]
creation_date = "2020/06/10"
integration = ["aws"]
maturity = "production"
updated_date = "2026/04/10"

[rule]
author = ["Elastic"]
description = """
Detects creation of a new AWS CloudTrail trail via CreateTrail API. While legitimate during onboarding or auditing
improvements, adversaries can create trails that write to attacker-controlled destinations, limit regions, or otherwise
subvert monitoring objectives.
"""
false_positives = [
    """
    Trail creations may be made by a system or network administrator. Verify whether the user identity should be making
    changes in your environment.
    """,
]
from = "now-6m"
index = ["filebeat-*", "logs-aws.cloudtrail-*"]
language = "kuery"
license = "Elastic License v2"
name = "AWS CloudTrail Log Created"
note = """
## Triage and analysis
Investigate ...
"""
references = ["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html"]
risk_score = 21
rule_id = "594e0cbf-86cc-45aa-9ff7-ff27db27d3ed"
severity = "low"
tags = ["Domain: Cloud", "Data Source: AWS"]
type = "query"
query = "event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success"

[[rule.threat]]
framework = "MITRE ATT&CK"

[[rule.threat.technique]]
id = "T1530"
name = "Data from Cloud Storage"
reference = "https://attack.mitre.org/techniques/T1530/"

[rule.threat.tactic]
id = "TA0009"
name = "Collection"
reference = "https://attack.mitre.org/tactics/TA0009/"
'''


@pytest.mark.asyncio
async def test_e2e_elastic_multiline_strings_regression(db_session):
    """A rule with multiline triple-quoted ``description`` /
    ``false_positives`` / ``note`` blocks must parse cleanly. Legacy
    `toml` package raised IndexError on these; stdlib `tomllib` does
    not. Regression for the silent-drop-70-AWS-rules incident."""
    d = await ingest_one(
        ElasticParser(),
        ElasticNormalizer("https://github.com/elastic/detection-rules"),
        "rules/integrations/aws/collection_cloudtrail_logging_created.toml",
        SAMPLE_ELASTIC_AWS_MULTILINE_RULE,
        db_session,
    )
    assert d.source == "elastic"
    assert d.title == "AWS CloudTrail Log Created"
    assert "T1530" in d.mitre_techniques
    assert "TA0009" in d.mitre_tactics
    # Multiline description body should be intact, not truncated.
    assert "CreateTrail API" in (d.description or "")


@pytest.mark.asyncio
async def test_e2e_splunk(db_session):
    d = await ingest_one(
        SplunkParser(),
        SplunkNormalizer("https://github.com/splunk/security_content"),
        "detections/endpoint/windows_powershell_encoded_command.yml",
        SAMPLE_SPLUNK_RULE,
        db_session,
    )
    assert d.source == "splunk"
    assert d.title == "Suspicious PowerShell Command"
    assert d.language == "spl"
    # MITRE technique routed from tags.mitre_attack_id
    assert "T1059.001" in d.mitre_techniques
    # Splunk URL points at the develop branch (not master)
    assert d.source_rule_url is not None
    assert "/develop/" in d.source_rule_url
    # Embedded `date` lands as rule_created_date
    assert d.rule_created_date is not None


@pytest.mark.asyncio
async def test_e2e_sentinel(db_session):
    d = await ingest_one(
        SentinelParser(),
        SentinelNormalizer("https://github.com/Azure/Azure-Sentinel"),
        # Sentinel can_parse() requires the path to contain "/solutions/"
        # — a leading-slash substring check. Real production paths are
        # `Azure-Sentinel/Solutions/.../Analytic Rules/...` (the repo dir
        # contributes the leading segment). Mirror that here.
        "Azure-Sentinel/Solutions/Microsoft Defender for Cloud Apps/Analytic Rules/MailForwardingFromO365.yaml",
        SAMPLE_SENTINEL_RULE,
        db_session,
    )
    assert d.source == "sentinel"
    assert d.title == "Mail Forwarding Configured to External Address"
    assert d.language == "kql"
    # Sentinel's auto-default author when none in YAML
    assert d.author == "Microsoft"
    # KQL table extraction → canonical taxonomy:
    #   OfficeActivity → microsoft_365 + audit_event.
    # Note: taxonomy_matched and taxonomy_fingerprint live only on the
    # in-memory NormalizedDetection — they're not persisted to the
    # Detection row so we can't read them back from the DB here.
    assert "microsoft_365" in d.platforms
    assert "audit_event" in d.event_types
    # MITRE technique pulled from relevantTechniques
    assert "T1114.003" in d.mitre_techniques
    # Bare threat-actor tag passes through verbatim
    assert "NOBELIUM" in d.tags


@pytest.mark.asyncio
async def test_e2e_sublime(db_session):
    d = await ingest_one(
        SublimeParser(),
        SublimeNormalizer("https://github.com/sublime-security/sublime-rules"),
        "detection-rules/attachment/qakbot_phishing.yml",
        SAMPLE_SUBLIME_RULE,
        db_session,
    )
    assert d.source == "sublime"
    assert d.title == "Phishing attachment from QakBot delivery campaign"
    assert d.language == "mql"
    # Sublime is always email-context — legacy column forced to email
    assert "email" in d.platforms
    # `Malfam: QakBot` tag preserved verbatim (Threat Pulse extracts it)
    assert "Malfam: QakBot" in d.tags


@pytest.mark.asyncio
async def test_e2e_elastic_protections(db_session):
    d = await ingest_one(
        ElasticProtectionsParser(),
        ElasticProtectionsNormalizer(
            "https://github.com/elastic/protections-artifacts"
        ),
        "behavior/rules/windows/credential_access_lsass_handle.toml",
        SAMPLE_ELASTIC_PROTECTIONS_RULE,
        db_session,
    )
    assert d.source == "elastic_protections"
    assert d.title == "Suspicious LSASS Handle Acquisition"
    assert d.language == "eql"
    assert d.author == "Elastic"
    # Behavior rules on a recognised OS get a process event_category
    assert "process_creation" in d.event_types
    # MITRE sub-technique pulled from nested rule.threat structure
    assert "T1003.001" in d.mitre_techniques
    # Endpoint-class data source attached -- canonical token
    assert "elastic_defend" in d.data_sources


@pytest.mark.asyncio
async def test_e2e_elastic_hunting(db_session):
    d = await ingest_one(
        ElasticHuntingParser(),
        ElasticHuntingNormalizer("https://github.com/elastic/detection-rules"),
        "hunting/aws/persistence_aws_iam_user_addition.toml",
        SAMPLE_ELASTIC_HUNTING_RULE,
        db_session,
    )
    assert d.source == "elastic_hunting"
    assert d.title == "AWS IAM User Created Outside Allowed Roles"
    # ES|QL vendor symbol normalized to esql canonical token
    assert d.language == "esql"
    # Product → platform mapping
    assert "aws" in d.platforms
    assert "T1136.003" in d.mitre_techniques
    # Hunting category default
    assert "hunting_query" in d.event_types


@pytest.mark.asyncio
async def test_e2e_lolrmm(db_session):
    d = await ingest_one(
        LOLRMMParser(),
        LOLRMMNormalizer("https://github.com/magicsword-io/LOLRMM"),
        # LOLRMM can_parse() requires the path to contain BOTH
        # "detections" and "sigma". Real production layout is
        # `LOLRMM/detections/sigma/<tool>.yml`.
        "detections/sigma/AnyDesk.yml",
        SAMPLE_LOLRMM_RULE,
        db_session,
    )
    assert d.source == "lolrmm"
    assert d.title == "AnyDesk Remote Access Tool Execution"
    assert d.language == "sigma"  # LOLRMM uses Sigma format
    assert "windows" in d.platforms  # forced default for RMM rules
    assert "process_creation" in d.event_types
    # MITRE technique routed from attack.t1219 tag
    assert "T1219" in d.mitre_techniques
    # Bare lolrmm tag preserved
    assert "lolrmm" in d.tags
    # Embedded Sigma-style date present
    assert d.rule_created_date is not None
    assert d.rule_created_date.year == 2023


@pytest.mark.asyncio
async def test_e2e_google_secops(db_session):
    d = await ingest_one(
        GoogleSecOpsParser(),
        GoogleSecOpsNormalizer("https://github.com/chronicle/detection-rules"),
        "rules/community/aws/cloudtrail/aws_console_login_without_mfa.yaral",
        SAMPLE_GOOGLE_SECOPS_RULE,
        db_session,
    )
    assert d.source == "google_secops"
    assert d.title == "AWS Console Login Without MFA"
    # Chronicle rules are YARA-L 2.0 -- canonical language token.
    assert d.language == "yaral"
    # Explicit `platform = "AWS"` meta -> canonical `aws`.
    assert "aws" in d.platforms
    assert "aws" in d.platforms
    # Explicit `data_source = "AWS CloudTrail"` meta resolves the
    # canonical data_source AND the implied api_call event_type.
    assert "aws_cloudtrail" in d.data_sources
    assert "aws_cloudtrail" in d.data_sources
    assert "api_call" in d.event_types
    # MITRE technique extracted from the mitre_attack_url URL form.
    assert "T1078.004" in d.mitre_techniques
    # Tactic name in meta block -> canonical TA ID.
    assert "TA0001" in d.mitre_tactics
    # Title-case severity normalized to lowercase canonical.
    assert d.severity == "low"
    # `type = "Alert"` isn't a status; community rules are stable.
    assert d.status == "stable"
    # Source URL deep-links into the right repo + branch.
    assert d.source_rule_url is not None
    assert "chronicle/detection-rules" in d.source_rule_url


@pytest.mark.asyncio
async def test_e2e_okta(db_session):
    d = await ingest_one(
        OktaParser(),
        OktaNormalizer("https://github.com/okta/customer-detections"),
        "detections/admin_console_login_weak_mfa.yml",
        SAMPLE_OKTA_RULE,
        db_session,
    )
    assert d.source == "okta"
    assert d.title == "Access to Admin Console with Weak MFA Factor"
    # Multi-query rule with OIE + Datadog -- primary picks OIE (priority
    # OIE > spl > datadog), so the canonical language tag is `oie`.
    assert d.language == "oie"
    # Author is list-of-strings in YAML -> joined to display string.
    assert "Okta" in d.author
    # Always-includes contract: platform=okta, data_source=okta_system_log,
    # event_type=authentication.
    assert "okta" in d.platforms
    assert "okta" in d.platforms
    assert "okta_system_log" in d.data_sources
    assert "authentication" in d.event_types
    # MITRE extracted from threat.Tactic (display names) + threat.Technique
    # (Tnnnn: name dict keys).
    assert "T1078" in d.mitre_techniques
    assert "TA0001" in d.mitre_tactics
    # Severity defaulted to medium (upstream YAML doesn't carry it).
    assert d.severity == "medium"
    # Embedded YAML dates round-trip through `parse_date`.
    assert d.rule_created_date is not None
    assert d.rule_created_date.year == 2025
    # Source URL uses the `master` branch (Okta's default).
    assert d.source_rule_url is not None
    assert "okta/customer-detections" in d.source_rule_url
    assert "/blob/master/detections/" in d.source_rule_url


@pytest.mark.asyncio
async def test_e2e_auth0(db_session):
    d = await ingest_one(
        Auth0Parser(),
        Auth0Normalizer("https://github.com/auth0/auth0-customer-detections"),
        "detections/refresh_token_reuse.yml",
        SAMPLE_AUTH0_RULE,
        db_session,
    )
    assert d.source == "auth0"
    assert d.title == "Refresh Token Reuse Detection"
    # Auth0 ships rules in Sigma format WITH a Splunk implementation;
    # the normalizer prefers Splunk as the analyst-facing primary,
    # so language=`spl` and detection_logic is the SPL query.
    assert d.language == "spl"
    assert "index=auth0" in d.detection_logic
    # Always-includes contract: platform=auth0, data_source=auth0_logs,
    # event_type=authentication (per mappings/auth0.yaml).
    assert "auth0" in d.platforms
    assert "auth0_logs" in d.data_sources
    assert "authentication" in d.event_types
    # MITRE techniques extracted from `attack.t<id>` Sigma tags via
    # the shared Sigma tag MITRE extractor.
    assert "T1550.001" in d.mitre_techniques
    assert "T1078" in d.mitre_techniques
    # Severity normalized from Sigma `level` field.
    assert d.severity == "medium"
    assert d.status == "experimental"
    # Source URL uses Auth0's default `main` branch.
    assert d.source_rule_url is not None
    assert "auth0/auth0-customer-detections" in d.source_rule_url
    assert "/blob/main/detections/" in d.source_rule_url


class _StubPantherDiscovery:
    """In-test discovery stand-in; supplies the .py sibling that the
    parser expects to read via get_sibling_content."""

    def __init__(self, py_body: str):
        self.py_body = py_body

    def get_sibling_content(self, repo_name, rel_path, extension):
        return self.py_body if extension == ".py" else None

    def get_rule_content(self, repo_name, rel_path):
        return None  # no deprecated.txt for this fixture


@pytest.mark.asyncio
async def test_e2e_panther(db_session):
    """End-to-end pipeline for a Panther rule: YAML metadata + .py
    sibling both surface, LogType resolves through the taxonomy
    mapping, MITRE colon-format splits into tactics + techniques,
    non-MITRE reports become prefixed tags."""
    disco = _StubPantherDiscovery(SAMPLE_PANTHER_RULE_PY)
    d = await ingest_one(
        PantherParser(disco),
        PantherNormalizer("https://github.com/panther-labs/panther-analysis"),
        "rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml",
        SAMPLE_PANTHER_RULE_YML,
        db_session,
    )
    assert d.source == "panther"
    assert d.title == "CloudTrail Was Stopped"
    # rule_id is Panther's dotted human-readable form, not a UUID.
    assert d.rule_id == "AWS.CloudTrail.Stopped"
    # .py source becomes detection_logic verbatim; language reflects it.
    assert d.language == "python"
    assert 'event.get("eventName") == "StopLogging"' in d.detection_logic
    # LogTypes -> canonical taxonomy via the Panther vendor resolver.
    assert "aws" in d.platforms
    assert "aws_cloudtrail" in d.data_sources
    assert "api_call" in d.event_types
    # MITRE (colon-joined format) split correctly.
    assert "TA0005" in d.mitre_tactics
    assert "T1562.008" in d.mitre_techniques
    # Severity from Panther enum -> canonical.
    assert d.severity == "high"
    # Non-MITRE report families as `report:*` tags.
    assert "report:cis" in d.tags
    # Source URL uses Panther's default `develop` branch.
    assert d.source_rule_url is not None
    assert "panther-labs/panther-analysis" in d.source_rule_url
    assert "/blob/develop/rules/" in d.source_rule_url
