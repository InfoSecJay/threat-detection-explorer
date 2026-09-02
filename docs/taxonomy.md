# Telemetry Taxonomy

How Detection Explorer normalizes "where the data comes from" across 8
detection rule repositories with completely different schemas.

This is a technical reference for engineers who need to:

- Understand how a rule's `platforms` / `data_sources` / `event_types`
  values get computed from its source YAML/TOML.
- Add a new rule repository to the system (Issue 6 work).
- Edit a mapping when the canonical vocabulary changes or a vendor
  schema updates.
- Add a new canonical platform / data source / event type.

> **Status:** Phase 1 of 3 (Issue 2 from `TODO.md`). The new fields
> coexist with the legacy ones (`log_sources`, `platform`,
> `event_category`, `data_source_normalized`) until Phase 3 cuts the
> legacy fields out entirely.

---

## Design principles for event_type classification

These principles were formalized after the first review pass against
real sigma/lolrmm data. They apply to `event_types` specifically, but
the "no inference" rule applies to the other two dimensions too.

### 1. No inference from channel-level logsources

If a rule's logsource is a broad channel (e.g. `windows/security`,
`okta`, `m365`), we do NOT try to guess which event type(s) the rule
might be looking at. Windows Security log contains authentication
events (4624, 4625), process events (4688), and audit events (4728,
4732) all intermixed — a rule could be filtering for any of them. We
tag the rule with a single coarse event_type (`audit_event`) rather
than listing all plausible sub-types.

**Don't do this:**
```yaml
windows/security:
  event_types: [authentication, audit_event]   # inference — wrong
```

**Do this:**
```yaml
windows/security:
  event_types: [audit_event]                    # coarse but accurate
```

The refinement that IS allowed comes from the rule itself, not the
channel: when the rule's logic pins specific event IDs (extracted into
`extracted_event_ids`), `mappings/event_ids.yaml` says what those IDs
are and `taxonomy/event_ids.py::refine_event_types` replaces the
coarse tag with the dictionary's types (issue #16). So a
`windows/security` rule with `EventID: 4624` becomes `authentication`,
one with `EventID: [4688, 4720]` becomes `[account_management,
process_creation]`, and one with no EventID stays `audit_event`.

Rules of the second pass (all covered by
`tests/test_services/test_event_ids.py`):

- Only Windows-scoped rules (platform `windows` or a Windows data
  source) are refined, so a Linux rule with `type=1` never picks up
  the Sysmon meaning; within Windows the channel prefix (next section)
  keeps `security:1` from doing so either.
- Only `audit_event` / `unknown` are replaced. A specific type the
  vendor mapping produced (`process_creation` from Sigma's category,
  `authentication` from Sentinel's `securityevents`) is kept and
  unioned with the dictionary's types.
- If any of the rule's IDs is unknown to the dictionary, `audit_event`
  is kept alongside the refinement -- part of the rule is still
  unclassified.
- IDs whose meaning depends on the channel (8001-8004: NTLM audit vs
  AppLocker) are deliberately absent from the dictionary; a duplicate
  ID across providers fails the test suite.

The pass runs in `NormalizedDetection.__post_init__` so every source
gets it without per-normalizer wiring. The same dictionary backs
`GET /api/query/event-ids`, which the UI uses to label raw IDs
("4688 - Process created") in the Event ID facet, the filter pills and
the detail page.

#### Event IDs are channel-namespaced (#110)

Stored `extracted_event_ids` carry the log channel as a short prefix:
`sysmon:1`, `security:4688`, `powershell:4104`, `system:7045`,
`defender:1116`. A bare number is ambiguous -- EventID 1 is
ProcessCreate in Sysmon and something else in the System log -- so
`taxonomy/event_ids.py::namespace_event_ids` decides the prefix right
before refinement, in this order:

1. The rule's canonical data source, when it names exactly one Windows
   log (`sysmon`, `windows_security_event_log`, `windows_powershell`,
   `windows_defender_event_log`). A Security-channel rule that pins
   EventID 1 is stored as `security:1`, whatever the dictionary thinks
   "1" means.
2. Otherwise (generic `windows_event_logs`, or two channels at once) the
   dictionary's provider for that number.
3. Otherwise the value stays bare. Non-Windows rules are never touched
   (Auth0 / Okta codes are not Windows event IDs).

The System and Application logs map to the generic
`windows_event_logs` tier for exactly this reason: they are not the
Security log, and step 2 resolves their IDs per number.

Consumers: `lookup()` is prefix-aware (`security:1` is *unknown*, not
Sysmon ProcessCreate), so refinement never crosses channels. The
catalog `event_ids` filter and the query bar (`eventid:sysmon:1`,
`eventid:"security:4688"`) match a namespaced value exactly, while a
bare `eventid:4688` matches that number on any channel -- including
rows from before namespacing -- so old links keep working. The
dictionary endpoint is keyed by the namespaced id with `event_id`
carrying the bare number; `useEventIds` indexes both.

The ten canonical values that only this pass produces
(`account_management`, `privilege_use`, `policy_change`, `log_clear`,
`service_install`, `service_event`, `scheduled_task`, `object_access`,
`share_access`, `directory_service_event`) are named after the Windows
Security auditing categories. They must never appear in a channel
mapping -- that would be exactly the inference this section forbids.

### 2. Full granularity when the vendor IS explicit

When Sigma gives us a specific `category`, we preserve it 1:1 as its
own canonical event_type. We do NOT collapse related categories into
a coarser parent.

**Don't do this:**
```yaml
windows/file_delete:
  event_types: [file_event]                     # lossy generalization
```

**Do this:**
```yaml
windows/file_delete:
  event_types: [file_delete]                    # preserve the specific kind
```

Detection engineers filter by these specific activities — a rule about
LSASS access (`process_access`) is meaningfully different from one
about process creation. Collapsing them makes the taxonomy less useful
for real analysts.

### 3. SaaS audit logs are `api_call`

Okta System Log, Microsoft 365 Unified Audit, GitHub Audit Log, GCP
Audit, Entra ID Audit, and AWS CloudTrail are all **API-call event
streams** at the architectural level. Per Okta's own docs, every
System Log entry represents an API call
([reference](https://developer.okta.com/docs/reference/api/event-types/)).
Same is true for the others — they're all REST-API event records.

We classify all of them as `api_call` for consistency. Tagging some
as `api_call` (AWS) and others as `audit_event` (Okta) would be
inconsistent — the feeds are architecturally identical.

Sign-in logs are the exception — Entra ID `signinlogs` and Azure AD
sign-in events are exclusively authentication activity, so they get
`authentication` instead of the generic `api_call`.

## The model: 3 orthogonal dimensions

Every detection rule answers three independent questions about its
telemetry source. We model each as a separate multi-value field on the
`Detection` row.

| Field | Question | Examples |
|---|---|---|
| `platforms` | **WHERE** does the telemetry live? | `windows`, `aws`, `okta`, `email` |
| `data_sources` | **WHAT** product/integration produces it? | `sysmon`, `aws_cloudtrail`, `crowdstrike_fdr` |
| `event_types` | **WHICH** activity is being detected? | `process_creation`, `network_connection`, `authentication` |

All three are `list[str]` so a rule can span multiple sources. Elastic's
cross-platform Node.js rule, for example, lists six index patterns and
naturally resolves to:

```python
platforms = ["windows", "linux", "macos"]
data_sources = ["elastic_defend", "sysmon", "windows_security_event_log",
                "crowdstrike_fdr", "sentinelone", "auditd"]
event_types = ["process_creation"]
```

When the vendor data doesn't supply enough info to determine a value,
the list contains `["unknown"]` — never silently empty. Users can
filter for "rules with unknown platform" to spot vendor coverage gaps.

---

## Data-source aliases and the near-duplicate gate

Teardown R04 (2026-08-31) found the live data-source facet carrying
synonym twins: `m365_*` vs `microsoft365_*`, `m365_defender` vs
`microsoft_defender_xdr` (one product, renamed), `azure_activity` vs
`azure_monitor_activity` (one feed, two delivery names), and per-stream
variants (`carbon_black_audit`, `sentinelone_activity`) sitting beside
their product id. A user filtering one spelling silently missed the
rules filed under the other.

Two mechanisms in `canonical.py` keep this from recurring:

1. **`DATA_SOURCE_ALIASES`** maps every accepted alternate spelling to
   one canonical id. Vendor mapping files may keep emitting the alias
   (the loader accepts them); `resolve_for_repo` rewrites to canonical
   before storage, so the facet only ever shows canonical ids.
2. **`find_near_duplicate_data_sources`** is a build gate
   (`test_taxonomy_aliases.py`): it fails the suite when a new canonical
   value is a spelling twin (token synonyms + depluralization) or a
   prefix extension (`carbon_black` / `carbon_black_audit` shape) of an
   existing one. Documented exceptions go in the test's allowlist,
   pair by pair — never by weakening the detector.

Rules for the table:

- **Collapse true synonyms only.** Distinct products stay distinct:
  `defender_endpoint` (MDE), `defender_cloud` (Defender for Cloud) and
  `windows_defender_event_log` (the Defender AV event channel) are three
  feeds, not three spellings.
- The canonical pick is the established convention (`m365_*`) or the
  spelling the corpus already uses most.
- An alias key must not appear in `DATA_SOURCES`; its target must.

### Generic buckets are a documented fallback tier

`application_logs`, `webserver_logs`, `proxy_logs`,
`network_traffic_logs`, `antivirus_logs`, `database_logs` and
`windows_event_logs` are **deliberately generic**: they exist for rules
whose vendor metadata names a telemetry *class* (a Sigma `webserver`
category, Panther's `Windows.EventLogs` LogType) rather than a product.
They are a fallback tier, not competitors to the named product feeds --
when the vendor names the product, map to the product feed; use the
generic only when the class is all the vendor says. Do not "upgrade" a
generic to a guessed product, and do not add a new generic when a named
feed exists.

---

## Module layout

```
backend/app/services/taxonomy/
├── __init__.py          # Public API: resolve_for_repo, PLATFORMS, ...
├── canonical.py         # SINGLE SOURCE OF TRUTH for valid values
├── resolver.py          # Dispatcher: routes a parsed rule to its vendor
├── _loader.py           # YAML loading + canonical validation
├── vendors/             # Per-vendor resolver functions
│   ├── sigma.py
│   ├── elastic.py
│   ├── elastic_hunting.py
│   ├── elastic_protections.py
│   ├── splunk.py
│   ├── sublime.py
│   ├── lolrmm.py
│   └── sentinel.py
└── mappings/            # Per-vendor YAML mapping rules (USER-EDITABLE)
    ├── sigma.yaml
    ├── elastic.yaml
    ├── elastic_hunting.yaml
    ├── elastic_protections.yaml
    ├── splunk.yaml
    ├── sublime.yaml
    ├── lolrmm.yaml
    └── sentinel.yaml
```

**Separation of concerns:**

- **`canonical.py`** defines what values are *legal*. Three frozensets:
  `PLATFORMS`, `DATA_SOURCES`, `EVENT_TYPES`. If you want to introduce
  a new value (e.g. add `proofpoint` as a platform), edit this file
  first.
- **`vendors/<name>.py`** implements the *logic* — how to walk the
  vendor-specific parsed rule and look up entries in the YAML.
- **`mappings/<name>.yaml`** is the *data* — the actual mapping rules
  for that vendor. Reviewable by humans, easy to edit.

---

## How resolution works

The flow for a single rule:

```
parsed rule (vendor schema)
        │
        ▼
resolve_for_repo("sigma", parsed)        ← public entry point
        │
        ▼
vendors/sigma.resolve(parsed)            ← vendor-specific logic
        │
        ├─ Reads parsed.log_source.product / service / category
        │
        ▼
load_mapping("sigma")                    ← reads mappings/sigma.yaml
        │
        ▼
Look up keys most-specific to least:
    "windows/powershell/process_creation"
    "windows/powershell"                 ← match!
    "windows/process_creation"
    "windows"
        │
        ▼
Return canonical sets:
    {platforms: ["windows"],
     data_sources: ["sysmon", "windows_security_event_log"],
     event_types: ["process_creation"]}
```

The resolver dispatcher (`resolver.py`) does final defensive validation:
ensures three lists, applies `[UNKNOWN]` fallback if any list is empty,
sorts and deduplicates.

---

## Mapping file formats

Each vendor has its own YAML structure tailored to its rule schema.
The structures are documented inline in each YAML file. Quick reference:

### `sigma.yaml`, `lolrmm.yaml` — keyed by `<product>[/<service>][/<category>]`

```yaml
by_key:
  windows/process_creation:           # most specific match wins
    platforms: [windows]
    data_sources: [sysmon, windows_security_event_log]
    event_types: [process_creation]
  windows:                             # broader fallback
    platforms: [windows]
    data_sources: [windows_security_event_log]
```

The resolver tries the most specific key first
(`product/service/category`) and falls back to less specific ones if no
match. First match wins; missing dimensions can be filled in from a
broader fallback.

### `elastic.yaml`, `elastic_hunting.yaml` — keyed by index pattern + integration

```yaml
index_patterns:
  "logs-aws.cloudtrail*":              # wildcard suffix matched by prefix
    platforms: [aws]
    data_sources: [aws_cloudtrail]
    event_types: [api_call]
  "logs-endpoint.events.process-*":
    platforms: [windows, linux, macos]  # multi-platform
    data_sources: [elastic_defend]
    event_types: [process_creation]

integrations:                          # fallback when no index matches
  okta:
    platforms: [okta]
    data_sources: [okta_system_log]
```

A single rule can list many indices — the resolver unions all matching
mappings. So a rule with `index: ["logs-aws.cloudtrail*", "logs-azure.signinlogs*"]`
gets `platforms: [aws, azure_ad]` and `data_sources: [aws_cloudtrail, entra_id_signin]`.

### `elastic_protections.yaml` — keyed by OS + EQL query head

```yaml
os_to_platforms:
  windows: windows
  linux: linux

eql_category_to_event_types:
  process: process_creation             # `process where ...` → process_creation
  network: network_connection
  file: file_event

always_includes:                        # every rule includes these
  data_sources: [elastic_defend]
```

Elastic Protections rules are agent-resident — there's no index. The
data source is always `elastic_defend`. Platforms come from `os_list`,
event type comes from parsing the EQL query head.

### `splunk.yaml` — keyed by `data_source` label (substring match)

```yaml
data_source_labels:
  "sysmon eventid 10":                  # exact match preferred
    platforms: [windows]
    data_sources: [sysmon]
    event_types: [process_creation]
  "sysmon":                             # falls through to substring match
    platforms: [windows]
    data_sources: [sysmon]
    event_types: [process_creation]
```

Splunk's `data_source` field carries free-form labels like
`"Sysmon EventID 10"` or `"ASL AWS CloudTrail"`. The resolver does
exact match first, then substring match.

### `sentinel.yaml` — keyed by connector ID + data type

```yaml
connectors:
  awssecurityhub:
    platforms: [aws]
    data_sources: [aws_security_hub]
    event_types: [audit_event]

data_types:                             # cross-cutting overrides
  securityalert:                        # SecurityAlert table from any connector
    data_sources: [siem_alert]
    event_types: [audit_event]
```

Sentinel rules carry `requiredDataConnectors` with `connectorId` +
`dataTypes`. We map by both. `data_types` overrides apply on top of
`connectors` matches.

### `sublime.yaml` — always email

```yaml
always_includes:
  platforms: [email]
  data_sources: [email_message_metadata]
  event_types: [email_message]
```

Every Sublime rule is email — no per-rule extraction needed.

---

## How to onboard a new rule repository

If you're adding a new vendor (e.g. Google SecOps, Panther) in Issue 6,
follow this checklist:

### 1. Pick the canonical values for this vendor's content

Sample 5-10 rules from the new repo. Identify which canonical
**platforms**, **data_sources**, and **event_types** they map to. If
the repo introduces a brand-new platform (e.g. Google SecOps content
about Chrome Enterprise), add it to `canonical.py` first.

### 2. Add the canonical values

In `backend/app/services/taxonomy/canonical.py`, add the new value(s)
to `PLATFORMS`, `DATA_SOURCES`, or `EVENT_TYPES` with a comment
explaining what the value covers.

### 3. Write a mapping YAML

Create `backend/app/services/taxonomy/mappings/<repo_name>.yaml`. Use
whichever structure matches the vendor's rule schema:

- Keyed by some categorical field → use a `by_key` map (Sigma/LOLRMM
  style)
- Index/path pattern matching → use `index_patterns` (Elastic style)
- Connector/integration ID → use a `connectors` map (Sentinel style)
- Free-form labels → use `data_source_labels` with substring matching
  (Splunk style)
- Implicit / always the same → use `always_includes`

When in doubt, copy the closest existing vendor YAML and adapt.

### 4. Write the vendor resolver

Create `backend/app/services/taxonomy/vendors/<repo_name>.py`. Pattern:

```python
from typing import TYPE_CHECKING
from app.services.taxonomy._loader import load_mapping

if TYPE_CHECKING:
    from app.parsers.base import ParsedRule

_MAPPING = load_mapping("<repo_name>")  # loads <repo_name>.yaml


def resolve(parsed: "ParsedRule") -> dict:
    """Resolve canonical taxonomy values for a parsed <vendor> rule."""
    platforms: set[str] = set()
    data_sources: set[str] = set()
    event_types: set[str] = set()

    # ... walk parsed rule fields, look up entries in _MAPPING,
    # ... union into the three sets

    return {
        "platforms": platforms,
        "data_sources": data_sources,
        "event_types": event_types,
    }
```

The function MUST return three lists/sets. The resolver dispatcher
applies `[UNKNOWN]` fallback if any are empty, so you don't need to
handle that yourself.

### 5. Register the resolver

Add an import to `vendors/__init__.py` and an entry to
`_VENDOR_RESOLVERS` in `resolver.py`.

### 6. Add tests

In `backend/tests/test_services/test_taxonomy.py`, add at least:

- One happy-path test for a representative rule.
- One test for the "unknown product" / empty parsed-rule case.

### 7. Run the test suite

```
cd backend && python -m pytest tests/test_services/test_taxonomy.py -v
```

If the YAML loader logs `Mapping <repo>.yaml references non-canonical
...` warnings on import, fix the typos in the YAML (or add the missing
canonical value). You will not get that far in practice:
`tests/test_services/test_mapping_integrity.py` loads every mapping
file with `strict=True` and fails the suite on the same condition --
added after `endpoint_behavior` reached production as a non-canonical
event_type on 63 Panther rules with only a warning to show for it
(issue #42).

### 8. Backfill existing data

Trigger a manual sync so the new resolver populates the taxonomy
columns for the new repo's rules:

```
POST /api/scheduler/trigger {"repository": "<repo_name>"}
```

---

## Editing existing mappings

The mapping YAML files are designed to be edited by humans.
`backend/app/services/taxonomy/_loader.py` validates references at
import time — if you accidentally write `data_sources: [crowdstrik_fdr]`
(typo), the worker will log a `WARNING` at startup but won't crash --
and the test suite will fail, which is the gate that actually matters.

Workflow:

1. Open the relevant `mappings/<repo>.yaml`.
2. Find the entry to change. Add/remove canonical values from the
   `platforms` / `data_sources` / `event_types` lists.
3. If you're using a value that doesn't exist yet, add it to
   `canonical.py` first.
4. Run the test suite locally to catch obvious problems.
5. Commit, push. The worker auto-redeploys; the next sync picks up the
   new mappings.

> **Tip:** during Phase 1, the new fields coexist with the legacy
> ones. To compare what the new resolver would produce vs. what the
> legacy code produced, query the database for both — both columns are
> populated.

---

## Adding a new canonical value

If a vendor introduces a new product or platform that doesn't fit any
existing canonical value:

1. Add the value to `canonical.py` with a short comment.
2. Add a mapping entry in the relevant `mappings/<vendor>.yaml`.
3. **(Future, after Phase 2)** Add a display name + color in
   `frontend/src/constants/taxonomy.ts`.
4. Re-run a sync to backfill the column for affected rules.

If the value is genuinely orthogonal (a real new dimension, not a new
value within an existing dimension), reach out for design discussion
before adding a 4th field — the 3-field model is intentional and
adding a 4th one is a significant change.

---

## What we deliberately did NOT model

- **`attack_types`** for Sublime rules (phishing, BEC, etc.) — that's
  a *threat-classification* dimension, not a telemetry-source one. It
  belongs in a separate field (or in `tags`). Out of scope for Issue 2.
- **MITRE ATT&CK tactics/techniques** — already a separate first-class
  dimension on the Detection model. Not part of taxonomy.
- **Severity, status, rule type** — already separate fields.
- **Detection methods** (e.g. Sublime's "Header analysis", "NLU") —
  too vendor-specific to normalize meaningfully.

---

## Migration phases (for context)

- **Phase 1 (Issue 2 first ship):** Add new fields. Both legacy and
  new fields are populated by every ingest. Nothing user-visible
  changes yet.
- **Phase 2:** Update API and frontend FilterPanel to read the new
  fields. Legacy fields are still in the DB but unused.
- **Phase 3:** Drop legacy fields entirely. Rename `taxonomy_*`
  columns to `platforms` / `data_sources` / `event_types`.

The phasing is to allow incremental rollout and testing without ever
breaking the live site.

## PowerShell logging event types (#47)

PowerShell script-block / module / classic-engine logging used to be
folded into `process_creation` "because the events record command
execution". That put every Sigma `windows/ps_script` rule and ~130
Splunk EventID 4104 rules in the same bucket as Sysmon 1 / 4688, and
contradicted principle 2 (full granularity when the vendor is explicit).
Since 2026-08-29 they are their own canonical values, mirroring Sigma:

| Canonical value | Sigma category | Windows event IDs (Microsoft-Windows-PowerShell/Operational) |
| :--- | :--- | :--- |
| `ps_script` | `ps_script` | 4104 |
| `ps_module` | `ps_module` | 4103 |
| `ps_classic` | `ps_classic_start`, `ps_classic_provider_start` | 400, 600, 800 |

The event-ID refinement pass applies the same values to Splunk / Sentinel
/ Elastic rules that pin those IDs, so a filter on `ps_script` is
cross-vendor. `process_creation` is now strictly process starts
(Sysmon 1, 4688, `process where ...`).
