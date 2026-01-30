# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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

### Changed
- Updated statistics endpoint to include `elastic_hunting` source
- Hero badge now shows "7 INTEL FEEDS ACTIVE" (previously 6)

### Fixed
- MITRE Coverage Matrix now correctly displays techniques that only have sub-technique coverage
- Invalid/deprecated MITRE techniques are now mapped or filtered from display
