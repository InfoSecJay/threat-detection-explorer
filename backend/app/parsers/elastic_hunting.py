"""Elastic Hunting Queries detection rule parser."""

import logging
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from app.parsers.base import BaseParser, ParsedRule

logger = logging.getLogger(__name__)


class ElasticHuntingParser(BaseParser):
    """Parser for Elastic Hunting Queries (TOML format with [hunt] section)."""

    @property
    def source_name(self) -> str:
        return "elastic_hunting"

    def can_parse(self, file_path: Path) -> bool:
        """Check if this is an Elastic Hunting rule file."""
        path_str = str(file_path).lower()

        # Must be TOML
        if not path_str.endswith(".toml"):
            return False

        # Must be in hunting directory
        if "hunting" not in path_str:
            return False

        # Exclude deprecated and test directories
        excluded = ["deprecated", "tests", "test", ".git"]
        return not any(ex in path_str.lower() for ex in excluded)

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        """Parse an Elastic Hunting TOML rule file."""
        try:
            data = tomllib.loads(content)

            # Get the hunt section (different from [rule] used in detection rules)
            hunt = data.get("hunt", {})
            if not hunt:
                logger.debug(f"Skipping {file_path}: no hunt section")
                return None

            # Required field: name
            name = hunt.get("name")
            if not name:
                logger.debug(f"Skipping {file_path}: no name")
                return None

            # Get query (detection logic) - it's a list of queries
            query_list = hunt.get("query", [])
            if isinstance(query_list, list):
                query = "\n\n---\n\n".join(query_list) if query_list else ""
            else:
                query = str(query_list)

            # Extract MITRE info from mitre field (simple list of technique IDs)
            mitre_attack = self._extract_mitre(hunt)

            # Determine platform from file path or integration field
            integration = hunt.get("integration", [])
            log_source = self._determine_log_source(file_path, integration)

            # Get language
            language_list = hunt.get("language", [])
            language = language_list[0] if language_list else "ES|QL"

            # Build tags from integration
            tags = ["hunting_query", "threat_hunting"]
            if integration:
                for integ in integration:
                    if isinstance(integ, str):
                        tags.append(integ.lower())

            # Notes can serve as additional context
            notes = hunt.get("notes", [])

            # Build description from description + notes
            description = hunt.get("description", "")
            if notes:
                notes_text = "\n\nNotes:\n" + "\n".join(f"- {note}" for note in notes)
                description = (description or "") + notes_text

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=name,
                description=description,
                author=hunt.get("author", "Elastic"),
                status="stable",  # Hunting queries in main branch are stable
                severity="medium",  # Hunting queries are proactive, default to medium
                log_source=log_source,
                tags=tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=query,
                false_positives=[],  # Hunting queries don't have false positives field
                extra={
                    "uuid": hunt.get("uuid"),
                    "license": hunt.get("license"),
                    "integration": integration,
                    "language": language_list,
                    "notes": notes,
                },
            )

        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def _extract_mitre(self, hunt: dict) -> dict:
        """Extract MITRE ATT&CK techniques from mitre field.

        The hunt section has a simple 'mitre' field with technique IDs.
        Example: mitre = ['T1078.004']
        """
        tactics = []
        techniques = []

        mitre = hunt.get("mitre", [])
        if not mitre:
            return {"tactics": tactics, "techniques": techniques}

        # Ensure it's a list
        if not isinstance(mitre, list):
            mitre = [mitre]

        for tech_id in mitre:
            if isinstance(tech_id, str) and tech_id.startswith("T"):
                if tech_id not in techniques:
                    techniques.append(tech_id)

        return {"tactics": tactics, "techniques": techniques}

    def _determine_log_source(self, file_path: Path, integration: list) -> dict:
        """Determine log source from file path and integration field."""
        path_str = str(file_path).lower()

        product = "endpoint"
        category = "hunting"

        # Check file path for platform hints
        if "/windows/" in path_str or "\\windows\\" in path_str:
            product = "windows"
        elif "/linux/" in path_str or "\\linux\\" in path_str:
            product = "linux"
        elif "/macos/" in path_str or "\\macos\\" in path_str:
            product = "macos"
        elif "/aws/" in path_str or "\\aws\\" in path_str:
            product = "aws"
        elif "/azure/" in path_str or "\\azure\\" in path_str:
            product = "azure"
        elif "/okta/" in path_str or "\\okta\\" in path_str:
            product = "okta"
        elif "/llm/" in path_str or "\\llm\\" in path_str:
            product = "llm"
        elif "/cross-platform/" in path_str or "\\cross-platform\\" in path_str:
            product = "cross_platform"

        # Also check integration field
        if integration:
            integ_lower = [str(i).lower() for i in integration]
            if "okta" in integ_lower:
                product = "okta"
            elif "aws" in integ_lower or any("aws" in i for i in integ_lower):
                product = "aws"
            elif "azure" in integ_lower or any("azure" in i for i in integ_lower):
                product = "azure"

        return {"product": product, "category": category}
