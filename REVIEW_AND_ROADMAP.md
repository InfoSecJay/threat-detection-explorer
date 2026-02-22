# Threat Detection Explorer - Review & Roadmap

**Review Date:** February 2026
**Last Updated:** February 2026 (Post field-extraction implementation)

---

## Executive Summary

The Threat Detection Explorer has evolved from a **read-only catalog** into a **rule content engineering platform**. With the addition of field-level parsing and observable extraction across 4 SIEM formats, the platform now deeply understands detection logic — not just metadata. This positions it to support LLM-assisted comparison, gap analysis, quality assessment, and eventually rule generation.

**Inspiration & Alignment:**
- [security-detections-mcp](https://github.com/mhaggis/security-detections-mcp) by Michael Haag — extract-at-index-time approach, cross-vendor field-level search, process/file/registry extraction from query logic
- [UC-16: Observable/Artifact Extraction](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/16-observable-artifact-extraction.md) — tiered extraction (deterministic first, LLM for complex), structured observable output
- [UC-17: Rule Comparison & Gap Analysis](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/17-rule-comparison-and-gap-analysis.md) — pairwise observable-level comparison, coverage depth, CTI alignment
- [UC-18: Rule Quality Assessment](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/18-rule-quality-assessment.md) — 5-dimension quality scoring (specificity, description alignment, MITRE mapping, evasion gaps, severity)
- [UC-19: Detection Rule Generation](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/19-detection-rule-generation.md) — LLM-assisted cross-platform rule generation and translation

---

## Current Architecture

### What's Built

| Layer | Capability | Status |
|-------|-----------|--------|
| **Ingestion** | 8 sources (SigmaHQ, LOLRMM, Elastic, Splunk, Sentinel, Sublime, Elastic Hunting, Elastic Protections) | Done |
| **Normalization** | Unified schema across all formats with platform/event_category/data_source taxonomy | Done |
| **Field Extraction** | Parse detection logic for observables across Sigma, Elastic (EQL/KQL/Lucene), Splunk (SPL), Sentinel (KQL) | Done |
| **Observable Storage** | Extracted fields, Event IDs, process names, file paths, registry keys, network indicators, source tables, structured observables, query complexity | Done |
| **Search** | Full-text + metadata filters (source, severity, MITRE, platform, language, etc.) | Done |
| **Comparison** | Side-by-side rule comparison with field-level diff | Done |
| **Coverage Matrix** | MITRE ATT&CK heatmap with technique/sub-technique drill-down | Done |
| **Export** | JSON/CSV export with filters | Done |
| **Industry Intel** | Trending techniques, GitHub releases | Done |

### Field Extraction Detail

The field extractor service (`backend/app/services/field_extractor.py`) parses detection logic at ingestion time and stores structured observables. This is the foundation for all downstream rule content engineering features.

**Formats parsed:**
- **Sigma** — YAML detection sections, selection/filter/condition blocks, modifier expansion (`|contains`, `|endswith`, `|re`)
- **Elastic** — EQL (`event where condition`), KQL (`field:value`), Lucene (`field:"value"`), sequences, thresholds
- **Splunk** — SPL pipes, tstats/datamodel references, `index=`/`sourcetype=`, field=value, IN operators, macros
- **Sentinel** — KQL table references, where/project/extend/summarize operators, let variables, union/join

**Formats NOT parsed (intentionally):**
- Sublime (MQL) — different paradigm, low priority
- Elastic Hunting (ES|QL) — investigation queries, not detection rules
- Elastic Protections — behavioral rules with complex endpoint-specific logic

**Extracted observables per rule:**
- `extracted_fields_used` — all field names referenced in the query
- `extracted_event_ids` — Windows Event IDs (e.g., 4688, 1, 10)
- `extracted_process_names` — process executables (e.g., powershell.exe, cmd.exe)
- `extracted_file_paths` — file system paths
- `extracted_registry_keys` — registry paths
- `extracted_network_indicators` — IPs, domains, ports
- `extracted_source_tables` — data source tables (e.g., DeviceProcessEvents, SecurityEvent)
- `extracted_observables` — full structured list with type/subtype/negation
- `query_complexity` — simple, moderate, complex (based on joins, sequences, aggregations)

**Test coverage:** 79 unit tests across 4 format extractors (all passing).

---

## Roadmap

### P0 — Foundation (Field-Level Intelligence)

#### 1. Field-Level Search & Filters
**Status:** Next up
**What:** Expose extracted fields as searchable API parameters and frontend filters.

- Add search params: `event_ids`, `process_names`, `fields_used`, `source_tables`, `query_complexity`
- Backend: `backend/app/services/search.py` — JSON-based list search (matching existing `mitre_techniques` pattern)
- Frontend: `frontend/src/components/FilterPanel.tsx` — Event ID input, process name multi-select, complexity toggle
- Frontend: Observable display on rule detail view

**Why P0:** The extracted data exists in the database but isn't queryable yet. This unlocks the core value of field extraction — "find all rules checking for Event ID 4688" or "find all rules monitoring powershell.exe".

#### 2. Rule Quality Scoring (Deterministic)
**Status:** Schema ready (quality_score, quality_details columns exist)
**What:** Score rules on 5 dimensions without LLM, aligned with [UC-18](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/18-rule-quality-assessment.md).

Dimensions:
1. **Metadata Completeness** (0-10) — description, references, false_positives, author, MITRE mapping
2. **Detection Specificity** (0-10) — fields used count, exclusion filters, specific values vs wildcards
3. **MITRE Mapping Quality** (0-10) — has techniques (not just tactics), sub-techniques, platform match
4. **Documentation Quality** (0-10) — description length, references count, false positives documented
5. **Query Complexity Score** (0-10) — multi-condition, appropriate complexity for claimed technique

**New file:** `backend/app/services/quality_scorer.py`
**Why P0:** Quality scoring is deterministic (no LLM needed), low effort, high value. Helps engineers find the best rule for their use case.

#### 3. Observable-Level Rule Comparison
**Status:** Foundation ready (observables extracted and stored)
**What:** Enhance the existing comparison page with observable-level analysis, aligned with [UC-17](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/17-rule-comparison-and-gap-analysis.md).

- Compare rules by what they actually detect (observables), not just metadata
- Show which fields each rule checks, what values they look for
- Identify coverage gaps: "Rule A checks CommandLine but not ParentImage"
- Cross-vendor observable alignment: Sigma's `Image` = ECS's `process.executable` = Splunk's `Processes.process`

---

### P1 — Intelligence Layer

#### 4. Cross-Vendor Gap Analysis
**What:** Given a MITRE technique, analyze detection depth across all vendors.

- Per-technique: which observables are covered by which sources?
- Identify blind spots: "All 5 rules for T1059.001 check process names, but none check parent process or command line args"
- CTI alignment: which techniques have no behavioral detection (only IOC-based)?
- Surface in coverage matrix: quality-weighted coverage, not just rule count

#### 5. Duplicate/Similar Rule Detection
**What:** Cluster rules that detect the same behavior across vendors.

- Observable-level similarity (rules checking same fields + similar values)
- Detection logic hashing for exact/near-duplicate identification
- "Best in class" recommendation per detection concept
- Group duplicates in search results

#### 6. Data Source Requirements Mapping
**What:** Answer "which rules can I actually run with my log sources?"

- Parse extracted `source_tables` and `fields_used` to determine data requirements
- "My Environment" profile — users select available log sources
- Filter: "Implementable" vs "Missing Data" rules
- Show specific missing telemetry per rule

---

### P2 — Operationalization

#### 7. Rule Translation Engine
**What:** Translate detection logic between SIEM formats.

- Start with Sigma as pivot format (Sigma→SPL, Sigma→KQL, Sigma→EQL)
- Leverage extracted observables for field mapping across vendor schemas
- Integrate with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) / pySigma pipelines
- UI: "Translate to..." dropdown on rule detail page

#### 8. SIEM-Native Export
**What:** Export in formats directly importable to SIEMs.

- Splunk: `.conf` savedsearches.conf
- Elastic: Security rule JSON (Kibana-importable)
- Sigma: YAML for pySigma pipelines
- Sentinel: ARM templates / KQL analytics rules

#### 9. Saved Searches & Collections
**What:** Let engineers save filter combinations and group related rules.

- Local storage for saved searches
- "My Collections" — curated rule sets (e.g., "Ransomware Detection Pack")
- Shareable collection URLs

#### 10. Version History
**What:** Track how rules change across re-ingestion.

- `detection_versions` table
- Diff between versions
- "History" tab on rule detail

---

### P3 — LLM-Assisted Engineering (Future)

#### 11. LLM-Assisted Quality Assessment
**What:** Extend deterministic quality scoring with LLM analysis, full [UC-18](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/18-rule-quality-assessment.md).

- Evasion gap analysis (could attackers bypass this rule?)
- Description-to-logic alignment (does the rule actually detect what it claims?)
- Severity appropriateness validation
- Improvement recommendations

#### 12. LLM-Assisted Observable Extraction
**What:** Handle complex/ambiguous rules the deterministic parser can't fully parse, per [UC-16](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/16-observable-artifact-extraction.md) tiered approach.

- Tier 1 (done): Deterministic regex/AST parsing
- Tier 2 (future): LLM for rules with complex logic, nested conditions, or novel patterns
- Confidence scoring for extracted observables

#### 13. Detection Rule Generation
**What:** LLM-assisted rule creation, aligned with [UC-19](https://github.com/InfoSecJay/ai-for-detection-engineering/blob/main/use-cases/rule-content-engineering/19-detection-rule-generation.md).

- Input: technique description, target platform, available telemetry
- Output: detection rule in target SIEM format
- Leverage the full rule library as context (what patterns work for similar techniques?)
- Multi-variant generation (IOC-based, behavioral, anomaly-based)
- Cross-platform generation from a single description

#### 14. MCP Server Integration
**What:** Expose the rule database via Model Context Protocol for external LLM tools, inspired by [security-detections-mcp](https://github.com/mhaggis/security-detections-mcp).

- Search rules by observable fields
- Compare cross-vendor coverage for a technique
- Generate rules in context of existing library
- Quality assessment via LLM tools

---

## Quick Wins

| Item | Effort | Status |
|------|--------|--------|
| Enable FastAPI Swagger docs | 1 line | Backlog |
| Keyboard shortcuts (j/k nav, / search) | Low | Backlog |
| Copy to clipboard for detection logic | Low | Done |
| EventID extraction from detection logic | Medium | Done (via field extractor) |

---

## Implementation Tracking

### Completed
- [x] 8-source ingestion pipeline (SigmaHQ, LOLRMM, Elastic, Splunk, Sentinel, Sublime, Elastic Hunting, Elastic Protections)
- [x] Unified normalization with platform/event_category/data_source taxonomy
- [x] Side-by-side rule comparison
- [x] MITRE ATT&CK coverage matrix
- [x] JSON/CSV export
- [x] Industry intel page
- [x] Copy to clipboard for detection logic
- [x] Field extraction service — Sigma, Elastic (EQL/KQL/Lucene), Splunk (SPL), Sentinel (KQL)
- [x] 79 unit tests for field extraction (all passing)
- [x] Database schema for extracted observables (10 new columns)
- [x] Normalizer integration (all 5 normalizers wired to extractors)
- [x] API schema updated to include extracted fields in responses

### In Progress
- [ ] Field-level search filters (API + frontend)
- [ ] Re-ingestion to populate extracted fields

### Backlog
- [ ] Rule Quality Scoring — deterministic (P0)
- [ ] Observable-Level Rule Comparison (P0)
- [ ] Cross-Vendor Gap Analysis (P1)
- [ ] Duplicate/Similar Rule Detection (P1)
- [ ] Data Source Requirements Mapping (P1)
- [ ] Rule Translation Engine (P2)
- [ ] SIEM-Native Export (P2)
- [ ] Saved Searches/Collections (P2)
- [ ] Version History (P2)
- [ ] LLM-Assisted Quality Assessment (P3)
- [ ] LLM-Assisted Observable Extraction (P3)
- [ ] Detection Rule Generation (P3)
- [ ] MCP Server Integration (P3)
- [ ] FastAPI Swagger Docs (Quick Win)
- [ ] Keyboard Shortcuts (Quick Win)

---

## Technical Reference

### Key Files

| File | Purpose |
|------|---------|
| `backend/app/services/field_extractor.py` | Core extraction service — 4 format extractors, ~80 field-to-type mappings |
| `backend/app/services/ingestion.py` | Ingestion pipeline — parse → normalize → extract → store |
| `backend/app/models/detection.py` | SQLAlchemy model with 40+ columns including extracted fields |
| `backend/app/normalizers/base.py` | Base normalizer with NormalizedDetection dataclass |
| `backend/app/normalizers/{sigma,elastic,splunk,sentinel,lolrmm}.py` | Format-specific normalizers |
| `backend/app/api/schemas.py` | Pydantic response schemas |
| `backend/app/services/search.py` | Search service (needs field-level params) |
| `backend/tests/test_field_extraction/` | 79 unit tests across 4 formats |

### Database Schema (Extracted Fields)

```
extracted_fields_used     JSON    All field names referenced in query
extracted_event_ids       JSON    Windows Event IDs
extracted_process_names   JSON    Process executable names
extracted_file_paths      JSON    File system paths
extracted_registry_keys   JSON    Registry paths
extracted_network_indicators JSON  IPs, domains, ports
extracted_source_tables   JSON    Data source tables
extracted_observables     JSON    Full structured observables [{field, values, type, subtype, negated}]
query_complexity          TEXT    simple | moderate | complex
quality_score             INT     0-100 (nullable, not yet populated)
quality_details           JSON    Per-dimension scores (nullable, not yet populated)
```
