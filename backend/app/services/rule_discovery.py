"""Rule discovery service for finding detection rules in repositories."""

import logging
from pathlib import Path
from typing import Generator

from app.config import settings

logger = logging.getLogger(__name__)


class RuleDiscoveryService:
    """Service for discovering detection rule files in repositories."""

    # File patterns for each vendor
    DISCOVERY_PATTERNS = {
        "sigma": {
            "include_patterns": ["rules/**/*.yml", "rules/**/*.yaml", "rules-*/**/*.yml", "rules-*/**/*.yaml"],
            "exclude_dirs": ["tests", "deprecated", "test", ".git"],
        },
        "elastic": {
            # Two trees:
            #   `rules/`                — production detection rules.
            #   `rules_building_block/` — sub-detections that don't fire
            #                             alerts on their own; consumed by
            #                             other rules. We ingest them with
            #                             a `building_block` tag so users
            #                             can filter in/out.
            "include_patterns": [
                "rules/**/*.toml",
                "rules_building_block/**/*.toml",
            ],
            # The `_building_block` exclusion is the LEGACY upstream dir
            # name (singular, leading underscore). Upstream renamed it to
            # `rules_building_block/` (plural, no underscore prefix). Kept
            # here for safety in case an old fork still uses it.
            "exclude_dirs": ["_deprecated", "deprecated", "tests", "test", ".git", "_building_block"],
        },
        "splunk": {
            "include_patterns": ["detections/**/*.yml", "detections/**/*.yaml"],
            "exclude_dirs": ["deprecated", "tests", "test", ".git"],
        },
        "sublime": {
            "include_patterns": ["detection-rules/**/*.yml", "detection-rules/**/*.yaml"],
            "exclude_dirs": ["tests", "deprecated", "test", ".git"],
        },
        "elastic_protections": {
            "include_patterns": ["behavior/rules/**/*.toml"],
            "exclude_dirs": ["deprecated", "tests", "test", ".git"],
        },
        "lolrmm": {
            "include_patterns": ["detections/sigma/**/*.yml", "detections/sigma/**/*.yaml"],
            "exclude_dirs": ["deprecated", "tests", "test", ".git"],
        },
        "elastic_hunting": {
            "include_patterns": ["hunting/**/*.toml"],
            "exclude_dirs": ["deprecated", "tests", "test", ".git"],
        },
        "google_secops": {
            # Chronicle community rules -- YARA-L 2.0 (.yaral). The
            # `rules/_deprecated/` tree carries a Windows-invalid
            # filename (`...?__sysmon.yaral`) so we never glob into
            # it. Sparse-checkout enforces this at clone time too.
            "include_patterns": ["rules/community/**/*.yaral"],
            "exclude_dirs": ["_deprecated", "deprecated", "tests", "test", ".git"],
        },
        "okta": {
            # Okta-authored detections live under `detections/`.
            # Sibling dirs (`hunts/`, `logs/`, `sample_osquery_checks/`,
            # `tests/`, `workflows/`) are intentionally NOT ingested --
            # they are reference material, not analytic rules.
            "include_patterns": ["detections/*.yml", "detections/*.yaml"],
            "exclude_dirs": [
                "hunts", "logs", "sample_osquery_checks",
                "tests", "test", "workflows", "deprecated", ".git",
            ],
        },
        "sentinel": {
            "include_patterns": [
                # Solutions/<vendor>/ packages — the main source
                "Solutions/**/Analytic Rules/*.yaml",
                "Solutions/**/Analytic Rules/*.yml",
                # NOTE: Hunting/Detection Queries are sparse-cloned so
                # they exist on disk, but `can_parse()` filters them out
                # — we don't ingest hunting queries as detection rules.
                # Keeping the globs here is harmless + lets can_parse()
                # reject them at parse time.
                "Solutions/**/Hunting Queries/*.yaml",
                "Solutions/**/Hunting Queries/*.yml",
                "Solutions/**/Detection Queries/*.yaml",
                "Solutions/**/Detection Queries/*.yml",
                # Root-level Detections/<table>/*.yaml — ~483 rules
                # grouped by KQL table name (AuditLogs, AWSCloudTrail,
                # Syslog, etc.). Previously missed entirely.
                "Detections/**/*.yaml",
                "Detections/**/*.yml",
                # NOTE: ASIM/ used to be in this list but it contains
                # ZERO analytic rules — only parser library functions
                # (`ASIM/lib/`), schema definitions (`ASIM/schemas/`),
                # dev scaffolding (`ASIM/dev/`), deploy templates
                # (`ASIM/deploy/`), tooling. The "ASIM rules" referenced
                # in older comments are actually under
                # `Solutions/.../Analytic Rules/` files that USE ASIM
                # parsers in their KQL queries. Discovered via the
                # coverage audit (382 PARSE_NONE files all under ASIM).
                # Summary rules — 7 alert-aggregation rules.
                "Summary rules/*.yaml",
                "Summary rules/*.yml",
            ],
            "exclude_dirs": ["deprecated", "tests", "test", ".git", "sample", "Sample"],
        },
    }

    def discover_rules(self, repo_name: str) -> Generator[Path, None, None]:
        """Discover all detection rule files in a repository.

        Args:
            repo_name: Name of the repository (sigma, elastic, splunk)

        Yields:
            Paths to detection rule files (relative to repo root)
        """
        patterns = self.DISCOVERY_PATTERNS.get(repo_name)
        if not patterns:
            logger.warning(f"No discovery patterns for repository: {repo_name}")
            return

        repo_path = settings.get_repo_path(repo_name)
        if not repo_path.exists():
            logger.warning(f"Repository not found: {repo_path}")
            return

        exclude_dirs = set(patterns["exclude_dirs"])

        for pattern in patterns["include_patterns"]:
            for file_path in repo_path.glob(pattern):
                # Check if file is in excluded directory
                if self._is_excluded(file_path, repo_path, exclude_dirs):
                    continue

                # Yield relative path
                yield file_path.relative_to(repo_path)

    def _is_excluded(self, file_path: Path, repo_path: Path, exclude_dirs: set[str]) -> bool:
        """Check if a file path should be excluded.

        Args:
            file_path: Absolute path to the file
            repo_path: Root path of the repository
            exclude_dirs: Set of directory names to exclude

        Returns:
            True if the file should be excluded
        """
        # Get path relative to repo
        rel_path = file_path.relative_to(repo_path)

        # Check each part of the path
        for part in rel_path.parts:
            if part.lower() in exclude_dirs:
                return True

        return False

    def count_rules(self, repo_name: str) -> int:
        """Count the number of detection rules in a repository.

        Args:
            repo_name: Name of the repository

        Returns:
            Number of rule files discovered
        """
        return sum(1 for _ in self.discover_rules(repo_name))

    def get_rule_content(self, repo_name: str, relative_path: Path) -> str | None:
        """Read the content of a rule file.

        Args:
            repo_name: Name of the repository
            relative_path: Path to the rule file relative to repo root

        Returns:
            File content as string, or None if file not found
        """
        repo_path = settings.get_repo_path(repo_name)
        full_path = repo_path / relative_path

        if not full_path.exists():
            logger.warning(f"Rule file not found: {full_path}")
            return None

        try:
            return full_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning(f"Error reading {full_path}: {e}")
            return None
