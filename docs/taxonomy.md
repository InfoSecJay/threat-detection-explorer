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
canonical value).

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
(typo), the worker will log a `WARNING` at startup but won't crash.

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
