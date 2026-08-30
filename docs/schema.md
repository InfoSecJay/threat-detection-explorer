# Detection Schema Reference

How every rule from every source ends up looking the same in our database.

This document is the **reader's guide** to the canonical detection schema.
It describes WHAT each field means, WHEN it gets populated, and HOW
vendor-specific fields map into it. The doc does not enumerate exhaustive
lists of canonical values that change frequently — for those, click
through to the source of truth:

| Want to know… | Authoritative source |
| --- | --- |
| Exact field types on the in-memory normalized object | [`backend/app/normalizers/base.py`](../backend/app/normalizers/base.py) (the `NormalizedDetection` dataclass) |
| Exact column names + types in the database | [`backend/app/models/detection.py`](../backend/app/models/detection.py) (the `Detection` SQLAlchemy model) |
| Exact field names + types in the public API response | [`backend/app/api/schemas.py`](../backend/app/api/schemas.py) (the `DetectionResponse` Pydantic schema) |
| Every canonical platform / data_source / event_type | [`backend/app/services/taxonomy/canonical.py`](../backend/app/services/taxonomy/canonical.py) |
| How the taxonomy resolver thinks per vendor | [`docs/taxonomy.md`](./taxonomy.md) |

**If this doc and the source disagree, the source wins.** A drift test in
`backend/tests/test_normalizers/test_schema_doc.py` ensures every column
in the `Detection` model is mentioned in this doc — schema additions
that forget to update the doc fail CI.

---

## At a glance

Every detection rule, regardless of source, ends up as a row with these
groups of fields:

1. **Identity** — who/what/where ids
2. **Core metadata** — title, description, author, language
3. **Status + severity** — canonical enums
4. **Canonical taxonomy** — `taxonomy_platforms`, `taxonomy_data_sources`,
   `taxonomy_event_types`. **The moat — what makes cross-vendor search work.**
5. **Legacy taxonomy** — `platform`, `event_category`,
   `data_source_normalized`, `log_sources`, `data_sources`. Coexist
   with the canonical fields; will be removed in Phase 3.
6. **MITRE ATT&CK** — tactics + techniques + tags + references
7. **Detection logic** — the human-readable query summary + raw content
8. **Extracted observables** — fields, event IDs, processes, paths,
   API actions… **The other half of the moat — what the rule actually checks.**
9. **Quality** — schema reserved, currently empty
10. **Dates** — rule created/modified + our sync timestamps

---

## 1. Identity

| Field | Type | Notes |
| --- | --- | --- |
| `id` | `str` (36) | Deterministic UUID-like, derived from `source + source_file`. Drives upserts. |
| `source` | enum | One of `sigma`, `elastic`, `splunk`, `sublime`, `elastic_protections`, `lolrmm`, `elastic_hunting`, `sentinel`, `google_secops`, `okta`, `auth0`. |
| `source_file` | `str` | Path within the source repo (e.g. `rules/windows/process_creation/foo.yml`). |
| `source_repo_url` | `str` | Canonical URL of the source repo. |
| `source_rule_url` | `str?` | Deep link to the rule file at the right vendor branch (e.g. `master`, `develop`). |
| `rule_id` | `str?` | The vendor's own internal id — Sigma `id:`, Elastic `rule_id`, Splunk `id`, Sublime/Sentinel/LOLRMM equivalents. Often a UUID. |

## 2. Core metadata

| Field | Type | Notes |
| --- | --- | --- |
| `title` | `str` | The rule's name. Required. |
| `description` | `str?` | Author's prose explaining what the rule detects. |
| `author` | `str?` | Single value. Elastic stores authors as a list; we join with `, `. Sentinel rules without an author default to `Microsoft`. |
| `language` | `str` | One of `sigma` / `eql` / `esql` / `spl` / `mql` / `kql` / `kuery` / `lucene` / `unknown`. Drives which field-extractor pass runs. |
| `raw_content` | `str` | The original file content, unchanged. |
| `detection_logic` | `str` | Human-readable summary of the query (often the query itself for SPL/KQL/MQL; YAML-formatted for Sigma). |

## 3. Status + severity

These are canonical enums. Vendor-specific values get mapped here.

| Field | Type | Allowed values | Vendor → canonical mappings |
| --- | --- | --- | --- |
| `status` | enum | `stable`, `test`, `experimental`, `deprecated`, `unsupported`, `unknown` | Sigma's vocabulary, preserved 1:1 (issue #26): `test` = works but not field-proven, `unsupported` = cannot run on current tooling. Elastic `production` → `stable`, `development` → `experimental`. Panther/pypanther `Enabled: false` → `experimental` (disabled upstream). Sources with no maturity concept (Sentinel, Okta, Sublime, Elastic hunting / protections) → `stable` -- they are published as production content, and `unknown` is reserved for values we could not parse (#47); `deprecated` never appears because every parser skips deprecated directories. Anything unrecognised → `unknown`. |
| `is_building_block` | bool | `true` / `false` | Building-block / signal-only rule: emits signal for other rules to correlate on rather than alerting by itself. Elastic `building_block_type` or the `rules_building_block/` tree; Panther `CreateAlert: false` or the `panther-signal` tag. Orthogonal to `status` (a building block can be `stable`). API: `building_block=true|false`; query bar: `building_block:true`. |
| `severity` | enum | `low`, `medium`, `high`, `critical`, `unknown` | Sigma `level` (`informational` → `low`). Splunk RBA risk score → bucketed. Sentinel `severity` → direct. |

## 4. Canonical taxonomy *(the moat)*

The cross-vendor "what does this rule cover" answer. Multi-OS rules can
have multiple values per dimension.

| Field | Type | Source |
| --- | --- | --- |
| `taxonomy_platforms` | `list[str]` | One or more canonical platform identifiers. |
| `taxonomy_data_sources` | `list[str]` | One or more canonical data-source identifiers. |
| `taxonomy_event_types` | `list[str]` | One or more canonical event-type identifiers. |
| `use_cases` | `list[str]` | Vendor-preserved analytic story / use-case labels. Populated for Splunk (`analytic_story` tag values), Elastic (`Use Case:` prefixed tags), Sublime (`attack_types` field). Empty on sources without a native concept. Casing is preserved as-is from the vendor. |
| `taxonomy_matched` | `bool` | True iff the resolver found a real mapping. False = the rule fell through to `["unknown"]` for every dimension. Drives the per-sync drift report. **Not persisted to the DB**, exists only on the in-memory `NormalizedDetection`. |
| `taxonomy_fingerprint` | `str` | Stable signature of the rule's logsource input. Used to group identical "unmapped" rules in drift reports. **Not persisted.** |

The full vocabulary is enumerated in
[`canonical.py`](../backend/app/services/taxonomy/canonical.py).
A high-level grouping for navigability:

- **Platforms**: endpoint OSes (`windows`, `linux`, `macos`), public
  cloud (`aws`, `azure`, `gcp`), identity / SaaS (`okta`, `microsoft_365`,
  `google_workspace`, `duo`, `onelogin`), DevOps (`github`, `gitlab`,
  `bitbucket`), `network_appliance`, `email`, container (`kubernetes`,
  `docker`), `llm`, `cross_platform`, `unknown`.
- **Data sources**: endpoint telemetry (Sysmon, auditd, Elastic Defend,
  Defender for Endpoint, CrowdStrike FDR…), cloud (CloudTrail,
  GuardDuty, Azure Activity, GCP Audit…), identity (Entra ID, Okta,
  Duo, Google Workspace…), network (Zeek, Suricata, Palo Alto…),
  email, application/webserver/AV/database (universal),
  alert streams (`siem_alert`, `elastic_siem_alerts`, `elastic_ml`).
- **Event types**: process activity (Sigma category 1:1 — `process_creation`,
  `image_load`, `process_access`, etc.), file activity, registry,
  network (`network_connection`, `dns_query`, `http_request`),
  `authentication`, `api_call`, `audit_event` (coarse fallback for
  channel-level logsources), `email_message`, `hunting_query`,
  `alert_correlation`, `platform_alert`, `ml_detection`, `unknown`.

**For depth on how the resolver picks values per vendor**, see
[`docs/taxonomy.md`](./taxonomy.md).

## 5. Legacy taxonomy *(scheduled for removal)*

Predates the canonical taxonomy. Coexists with it so consumers can
migrate at their own pace. Will be removed in Phase 3.

| Field | Type | Notes |
| --- | --- | --- |
| `log_sources` | `list[str]` | Raw flattened list (e.g. `["windows", "process_creation", "sysmon"]`). |
| `data_sources` | `list[str]` | Display-cased data-source hints (e.g. `["Sysmon", "Endpoint"]`). |
| `platform` | `str` | A SINGLE canonical value (vs the multi-valued `taxonomy_platforms`). |
| `event_category` | `str` | A SINGLE canonical value. |
| `data_source_normalized` | `str` | A SINGLE canonical value. |

Prefer the `taxonomy_*` fields when building new features.

## 6. MITRE ATT&CK + tags

| Field | Type | Notes |
| --- | --- | --- |
| `mitre_tactics` | `list[str]` | `TA####` ids. Elastic Hunting derives these from techniques via the MITRE service when the rule omits them. |
| `mitre_techniques` | `list[str]` | `T####` for parent techniques, `T####.###` for sub-techniques. Both forms coexist — a rule that tags `T1059` does NOT also tag `T1059.001`. |
| `mitre_groups` | `list[str]` | Raw ATT&CK Group IDs (`G####`) extracted from `attack.g*` tags. Populated for Sigma + LOLRMM (the sources that follow ATT&CK tag conventions); empty elsewhere. Display names resolved by `app.services.mitre_lookup`. Powers the Threat Spotlight module and the `mitre_groups` filter. |
| `mitre_software` | `list[str]` | Raw ATT&CK Software IDs (`S####`) extracted from `attack.s*` tags. Same source coverage as `mitre_groups`. Display names via `mitre_lookup`; unknown IDs fall through to their raw ID. |
| `tags` | `list[str]` | Free-form tags. Several conventions are deliberately preserved: |
| | | • Splunk's `analytic_story` tags keep their `story:` prefix (the Threat Pulse extractor reads it). |
| | | • Sublime's `Malfam: <Name>` tags pass through verbatim. |
| | | • Elastic's tags get lowercased and spaces → underscores. |
| `references` | `list[str]` | External links / CVE pages / threat-intel articles. |
| `false_positives` | `list[str]` | Author-noted FP scenarios. |
| `investigation_guide` | `str | null` | Vendor-authored investigation guide in markdown (Elastic `note`, with `setup` appended under its own heading). Null for sources without one; the rule page renders it under the Investigation guide tab. |

## 7. Detection logic + raw content

| Field | Type | Notes |
| --- | --- | --- |
| `detection_logic` | `str` | Human-readable summary of the rule's query. SPL → the SPL search itself. KQL → the KQL query. Sigma → YAML-formatted detection block. |
| `raw_content` | `str` | The original file content, unchanged. |
| `language` | `str` | (See section 2.) Drives which field-extractor pass runs over `detection_logic`. |

## 8. Extracted observables *(also the moat)*

These are PARSED out of `detection_logic` at ingestion time. They turn
"this rule mentions T1059" into "this rule actually checks `process.name`
against `powershell.exe` and `cmd.exe`."

| Field | Type | Populated when |
| --- | --- | --- |
| `extracted_fields_used` | `list[str]` | Every rule with parseable detection logic — every field name referenced. The most universal extracted column. |
| `extracted_event_ids` | `list[str]` | Windows-context rules (Sigma `EventID`, Sentinel `EventID == 4688`, etc.). |
| `extracted_process_names` | `list[str]` | Endpoint rules — process executable names (`powershell.exe`, `bash`, …). |
| `extracted_file_paths` | `list[str]` | Endpoint rules — file system paths. |
| `extracted_registry_keys` | `list[str]` | Windows endpoint rules — registry paths. |
| `extracted_network_indicators` | `list[str]` | IPs / domains / ports. |
| `extracted_source_tables` | `list[str]` | KQL `OfficeActivity`, SPL `Endpoint.Processes`, ES\|QL `FROM logs-aws.cloudtrail-*`, etc. **The single most useful extracted field for cross-vendor querying.** |
| `extracted_api_actions` | `list[str]` | Cloud / identity rules — `ConsoleLogin`, `CreateUser`, `Set-Mailbox`, `AssumeRole`. |
| `extracted_target_resources` | `list[str]` | Cloud rules — S3 buckets, IAM roles, Lambda functions. |
| `extracted_observables` | `list[dict]` | Full structured form: `{field, values, type, subtype, negated}`. The other extracted_* lists are convenience projections of this. |
| `query_complexity` | enum | `simple` / `moderate` / `complex` / `unknown`. Heuristic based on join count, sequence/threshold, aggregations. |

Approximate population rates as of v1.5 (12 031 rules):

- `extracted_fields_used`: ~93 % of rules
- `extracted_process_names`: ~28 %
- `extracted_api_actions`: ~18 %
- `extracted_event_ids`: ~8 %
- `extracted_target_resources`: ~1 %

## 9. Quality *(reserved)*

| Field | Type | Notes |
| --- | --- | --- |
| `quality_score` | `int?` | 0 – 100 metadata completeness (rubric v2, teardown F09): deterministic checks over metadata / ATT&CK / specificity / documentation / testability, scored ONLY against the checks the rule format can express (per-source capability profiles in `quality_score.INAPPLICABLE`) and renormalized to 100 over the applicable points. Not detection efficacy. |
| `quality_details` | `dict?` | Per-dimension `{score, of, issues, na}` + `raw` + `applicable_points`; `na` lists checks the format cannot express (shown as n/a in the UI, never failed). |

## 10. Dates

| Field | Type | Notes |
| --- | --- | --- |
| `rule_created_date` | `datetime?` | Embedded vendor field if present (Sigma `date`, Splunk `date`, LOLRMM `date`); git-log fallback elsewhere (Sentinel, Sublime, Elastic Protections, Elastic Hunting). |
| `rule_modified_date` | `datetime?` | Embedded vendor field if present (Sigma `modified`, Elastic `metadata.updated_date`, LOLRMM `modified`); git-log fallback elsewhere. Splunk has no embedded modified — always git-log. |
| `created_at` | `datetime` | Our sync timestamp — when the row was first stored. **Not the rule's birthday.** |
| `updated_at` | `datetime` | Our sync timestamp — refreshed on every upsert. |
| `sync_run_id` | `str?` | Id of the ingest run (the `sync_jobs.id` for scheduled runs) that last upserted the row. The atomic-swap cleanup deletes a source's rows whose run id is not the current one; `NULL` only on rows written before the column existed. |

---

## Per-source vendor → canonical mapping

This is the part that exists nowhere else. For each source, what the
vendor calls a thing and where it ends up in our schema.

For taxonomy-resolution depth (the tier system), see
[`docs/taxonomy.md`](./taxonomy.md).

### Sigma ([SigmaHQ/sigma](https://github.com/SigmaHQ/sigma))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `title` | `title` | direct |
| `id` | `rule_id` | UUID |
| `description` | `description` | direct |
| `author` | `author` | direct |
| `status` | `status` | direct (`stable` / `test` / `experimental` / `deprecated` / `unsupported`) |
| `level` | `severity` | `informational` → `low` |
| `logsource.product` / `category` / `service` | `taxonomy_*` | Tiered resolver via `taxonomy/mappings/sigma.yaml` |
| `tags` (with `attack.` prefix) | `mitre_tactics` / `mitre_techniques` | Routed by ID prefix (`attack.t...`, `attack.tactic...`) |
| `tags` (without `attack.`) | `tags` | passed through |
| `detection` block | `detection_logic` (YAML-formatted) + `extracted_*` | Parsed by the Sigma field extractor |
| `falsepositives` | `false_positives` | direct |
| `references` | `references` | direct |
| `date` | `rule_created_date` | embedded |
| `modified` | `rule_modified_date` | embedded |

### Elastic Detection Rules ([elastic/detection-rules](https://github.com/elastic/detection-rules))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `rule.name` | `title` | |
| `rule.rule_id` | `rule_id` | |
| `rule.description` | `description` | |
| `rule.author` (list) | `author` | joined with `, ` |
| `metadata.maturity` | `status` | `production` → `stable`, `development` → `experimental` |
| `rule.severity` | `severity` | direct |
| `rule.type` + `rule.language` | `language` | `eql` / `esql` / `kql` (kuery → kql) / `lucene` |
| `rule.index` + `metadata.integration` | `taxonomy_*` | Tiered resolver via `taxonomy/mappings/elastic.yaml`. ESQL rules also get index hints from `FROM` clause. |
| `rule.threat[].tactic` / `technique[].id` | `mitre_tactics` / `mitre_techniques` | direct |
| `rule.tags` | `tags` | lowercased, spaces → underscores |
| `rule.query` (or assembled for ML / threshold / new_terms) | `detection_logic` + `extracted_*` | |
| `rule.false_positives` | `false_positives` | direct |
| `rule.note` + `rule.setup` | `investigation_guide` | joined markdown |
| `rule.references` | `references` | direct |
| `metadata.creation_date` | `rule_created_date` | embedded |
| `metadata.updated_date` | `rule_modified_date` | embedded |
| `metadata.promotion = true` | `taxonomy_event_types` += `platform_alert` | Elastic "promotion" rules wrap external alerts |

### Splunk Security Content ([splunk/security_content](https://github.com/splunk/security_content))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `name` | `title` | |
| `id` | `rule_id` | |
| `description` | `description` | |
| `author` | `author` | direct |
| `status` | `status` | `production` → `stable` |
| RBA risk_objects[].score | `severity` | bucketed (≥80 critical, ≥60 high, ≥40 medium, else low) |
| `data_source` (list) | `taxonomy_*` (via resolver) + `data_sources` | Free-form vendor strings; mappings in `taxonomy/mappings/splunk.yaml` |
| `tags.mitre_attack_id` | `mitre_techniques` / `mitre_tactics` | Routed by ID prefix |
| `tags.kill_chain_phases` | `mitre_tactics` (additional) | Phase → tactic lookup |
| `tags.analytic_story` | `tags` (with `story:` prefix preserved) | Threat Pulse reads this |
| `tags.security_domain` | dropped from tags (duplicate of taxonomy) | Held in `extra` for taxonomy resolver |
| `tags.asset_type` | dropped from tags (duplicate of taxonomy) | |
| `search` | `detection_logic` + `extracted_*` | SPL extractor |
| `known_false_positives` | `false_positives` | |
| `references` | `references` | |
| `date` | `rule_created_date` | embedded; **no embedded modified date** — git-log fallback |
| (file's git history) | `rule_modified_date` | git log via `git_service` |

### Microsoft Sentinel ([Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `name` | `title` | |
| `id` | `rule_id` | |
| `description` | `description` | |
| (none) | `author` | defaults to `Microsoft` when missing |
| (always) | `status` | `stable` (Sentinel rules don't carry a maturity field) |
| `severity` | `severity` | direct |
| `query` | `detection_logic` + `extracted_*` | Always KQL — `language = "kql"` |
| KQL table names extracted from `query` | `taxonomy_*` (Tier 1) | `OfficeActivity` → `microsoft_365` + `audit_event`, etc. |
| `requiredDataConnectors[].connectorId` | `taxonomy_*` (Tier 2) | |
| `requiredDataConnectors[].dataTypes` | `taxonomy_*` (Tier 3) | |
| `Solutions/<vendor>/` folder name | `taxonomy_*` (Tier 4) | |
| `entityMappings[].entityType` | `taxonomy_event_types` (Tier 5, capability-only) | |
| `tactics` / `relevantTechniques` | `mitre_tactics` / `mitre_techniques` | direct |
| `tags` | `tags` | passed through verbatim (NOBELIUM, Solorigate, etc.) |
| (none) | `rule_created_date` / `rule_modified_date` | always git-log fallback |

### Sublime Rules ([sublime-security/sublime-rules](https://github.com/sublime-security/sublime-rules))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `name` | `title` | |
| `id` | `rule_id` | |
| `description` | `description` | |
| `authors[].name` (first) | `author` | first author taken |
| (always) | `status` | `stable` |
| `severity` | `severity` | direct |
| (always) | `language` | `mql` |
| (always) | `platform` | `email` (legacy column forced) |
| `source` (the MQL query) | `detection_logic` + `extracted_*` | Sublime field extractor |
| `tags` (incl. `Malfam: X`, `CVE-...`) | `tags` | passed through verbatim |
| `attack.*` tags | `mitre_tactics` / `mitre_techniques` | |
| `references` | `references` | |
| (none) | `rule_created_date` / `rule_modified_date` | always git-log fallback |

### Elastic Protections ([elastic/protections-artifacts](https://github.com/elastic/protections-artifacts))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `rule.name` | `title` | |
| `rule.id` | `rule_id` | |
| `rule.description` | `description` | |
| (always) | `author` | `Elastic` |
| (always) | `status` | `stable` |
| derived from `actions` or default | `severity` | bucketed |
| (always) | `language` | `eql` |
| `rule.os_list` | `taxonomy_platforms` (via resolver) | |
| `rule.query` (EQL) | `detection_logic` + `extracted_*` | |
| derived | `event_category` | defaults to `process` for OS rules |
| `rule.threat.*` | `mitre_tactics` / `mitre_techniques` | |
| (none) | `rule_created_date` / `rule_modified_date` | always git-log fallback |

### Elastic Hunting Queries ([elastic/detection-rules/hunting](https://github.com/elastic/detection-rules/tree/main/hunting))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `hunt.name` | `title` | |
| `hunt.uuid` | `rule_id` | |
| `hunt.description` | `description` | |
| `hunt.author` | `author` | |
| (always) | `status` | `experimental` (hunts are not deployed alerts) |
| `hunt.language[0]` | `language` | `ES\|QL` → `esql`; lowercases EQL/KQL/Lucene |
| `hunt.integration` | `taxonomy_*` (via resolver) | |
| `hunt.product` (windows / aws / okta / llm…) | `taxonomy_platforms` + legacy `platform` | Mapped 1:1 |
| `hunt.query` (list joined with `---`) | `detection_logic` + `extracted_*` | |
| `hunt.mitre` (techniques only, no tactics) | `mitre_techniques` | |
| (derived from techniques) | `mitre_tactics` | Resolved via the MITRE service |
| (always) | `event_category` | defaults to `hunting` |
| (none) | `rule_created_date` / `rule_modified_date` | always git-log fallback |

### LOLRMM ([magicsword-io/LOLRMM](https://github.com/magicsword-io/LOLRMM))

| Vendor field | Canonical field | Notes |
| --- | --- | --- |
| `title` | `title` | |
| `id` | `rule_id` | |
| `description` | `description` | |
| `author` | `author` | |
| `status` | `status` | direct (Sigma vocab) |
| `level` | `severity` | direct (Sigma vocab) |
| (always) | `language` | `sigma` (LOLRMM uses Sigma format) |
| `logsource.product` / `category` / `service` | `taxonomy_*` | Sigma-style resolver |
| (default) | `platform` | `windows` if resolver doesn't pick |
| (default) | `event_category` | `process` if resolver doesn't pick |
| `detection` block | `detection_logic` + `extracted_*` | Sigma extractor |
| `tags` (incl. `lolrmm`) | `tags` | passed through |
| `attack.*` tags | `mitre_tactics` / `mitre_techniques` | |
| `date` / `modified` | `rule_created_date` / `rule_modified_date` | embedded |

---

## Worked example — Sigma rule round-trip

A typical Sigma input rule:

```yaml
title: Suspicious PowerShell Encoded Command
id: fc99a948-6e26-4339-9d3d-c9450f60af26
status: stable
description: Detects encoded PowerShell command line.
author: Detection Engineer
date: 2023/01/01
modified: 2024/05/15
references:
  - https://example.com/threat-intel
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

After parse → normalize → extract, this becomes a `Detection` row with
(abbreviated):

```jsonc
{
  "id": "<deterministic uuid from sigma + file_path>",
  "source": "sigma",
  "source_file": "rules/windows/process_creation/proc_creation_susp_powershell.yml",
  "source_repo_url": "https://github.com/SigmaHQ/sigma",
  "source_rule_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/.../proc_creation_susp_powershell.yml",
  "rule_id": "fc99a948-6e26-4339-9d3d-c9450f60af26",
  "title": "Suspicious PowerShell Encoded Command",
  "description": "Detects encoded PowerShell command line.",
  "author": "Detection Engineer",
  "status": "stable",
  "severity": "high",
  "language": "sigma",
  "log_sources": ["windows", "process_creation"],
  "platform": "windows",
  "event_category": "process_creation",
  "data_source_normalized": "sysmon",
  "taxonomy_platforms": ["windows"],
  "taxonomy_data_sources": ["sysmon", "windows_security_event_log"],
  "taxonomy_event_types": ["process_creation"],
  "mitre_tactics": ["TA0002"],
  "mitre_techniques": ["T1059.001"],
  "tags": [],  // attack.* tags are routed to mitre_*, not kept here
  "references": ["https://example.com/threat-intel"],
  "false_positives": ["Legitimate admin scripts"],
  "extracted_fields_used": ["EventID", "Image", "CommandLine"],
  "extracted_event_ids": ["4688"],
  "extracted_process_names": ["powershell.exe"],
  "extracted_observables": [
    {"field": "EventID", "values": ["4688"], "type": "event_id", ...},
    {"field": "CommandLine", "values": ["-enc", "-EncodedCommand"], "type": "process", ...}
  ],
  "query_complexity": "moderate",
  "rule_created_date": "2023-01-01T00:00:00",
  "rule_modified_date": "2024-05-15T00:00:00",
  "detection_logic": "selection:\n  EventID: 4688\n  Image|endswith: \\powershell.exe\n  ..."
}
```

That's what a single canonical rule looks like — and the same shape comes
out the other end whether the input was a Sigma YAML, an Elastic TOML,
a Splunk YAML, or a Sentinel ARM template.
