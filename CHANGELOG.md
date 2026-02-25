# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **MITRE ATT&CK Tactic Heatmap** on comparison analytics: source-colored grid showing tactic coverage per vendor with intensity-scaled cells
- **Rule Preview Modal** on comparison page: click any detection card to view a condensed rule preview without leaving the comparison context
  - Shows header badges, description, MITRE mapping, extracted observables, metadata, and syntax-highlighted detection logic
  - Includes copy button and "View Full Detail" link to the full detection page
- **Comparison page analyst workspace overhaul**: filtering, sorting, enhanced detection cards, and dynamic grid layout
  - 6 filter types: source, platform, tactic, event category, complexity, and status
  - Sort by title, severity, source, or platform
  - Enhanced cards with source-colored borders, platform/language/MITRE badges
  - Grid columns preserved when filters narrow results (empty columns show placeholder)
- **Elastic Hunting Queries integration**: New data source for proactive threat hunting queries from the [elastic/detection-rules](https://github.com/elastic/detection-rules/tree/main/hunting) repository
  - 138 ES|QL hunting queries across Windows, Linux, macOS, AWS, Azure, Okta, and LLM platforms
  - Parser for TOML-based `[hunt]` section format
  - Normalizer with platform detection and integration field mapping
  - Custom purple hunting/crosshair icon in the UI
- MITRE ATT&CK technique validation and deprecated technique mapping
  - Maps 40+ deprecated technique IDs to their current equivalents (e.g., T1208 -> T1558.003)
  - Validates all techniques against the official MITRE ATT&CK framework
- Sub-technique rollup in MITRE Coverage Matrix
  - Parent techniques now include counts from their sub-techniques
  - Example: T1001 shows combined count from T1001, T1001.001, T1001.002, T1001.003
- Centralized source/severity constants in `frontend/src/constants/sources.ts`

### Changed
- Comparison analytics layout: 3 charts in top row (vendor bar, severity bar, compact pie) instead of 2+1
- CSV export expanded to 38 fields with all available detection metadata
- Updated statistics endpoint to include `elastic_hunting` source
- Hero badge now shows "8 SOURCES ACTIVE" (previously 7)

### Fixed
- CSV export crash on Sentinel rules containing dict-type tags
- Excel cell overflow on large rules (truncation at 32,000 chars)
- Future rule dates (author typos) discarded during ingestion
- MITRE Coverage Matrix now correctly displays techniques that only have sub-technique coverage
- Invalid/deprecated MITRE techniques are now mapped or filtered from display
