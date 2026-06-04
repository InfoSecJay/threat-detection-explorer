"""Auth0 customer-detections rule parser.

Auth0 detections are structurally **Sigma rules** with Auth0-specific
sibling fields. Every file follows the Sigma schema:

    title: <str>
    id: <UUID>
    status: experimental | stable
    description: <str>
    author: <str>
    date: <yyyy-mm-dd>
    modified: <yyyy-mm-dd>
    logsource:
      product: auth0
    detection:
      selection: {...}
      filter: {...}
      condition: <str>
    falsepositives: [<str>, ...]
    level: low | medium | high
    tags: [attack.t1562.007, attack.defense-evasion, ...]

Plus Auth0-specific siblings that we capture into `extra` so the rule
detail UI can surface them:

    splunk: |
      <SPL implementation>
    tenant_logs: |
      <Auth0-native tenant log query>
    prevention: [<str>, ...]
    comments: [<str>, ...]
    explanation: <str>

Some files use multi-doc YAML (a second `correlation:` rule) -- we
take the first doc only, consistent with how the Sigma parser handles
its own correlation rules.
"""

import logging
from pathlib import Path
from typing import Optional

import yaml

from app.parsers.base import BaseParser, ParsedRule
from app.parsers.sigma import SigmaParser

logger = logging.getLogger(__name__)


# Reuse the Sigma parser's MITRE tactic mapping -- Auth0 rules use the
# identical `attack.<tactic>` / `attack.t<id>` Sigma tag convention.
_SIGMA = SigmaParser()


class Auth0Parser(BaseParser):
    """Parser for Auth0 customer-detections (Sigma format + extras)."""

    @property
    def source_name(self) -> str:
        return "auth0"

    def can_parse(self, file_path: Path) -> bool:
        """Auth0 detections live under `detections/*.yml` at the repo
        root. The repo also has `test/`, `hunts/`-style siblings we
        don't want -- the path-component check handles that."""
        path_str = str(file_path).lower().replace("\\", "/")

        if not (path_str.endswith(".yml") or path_str.endswith(".yaml")):
            return False
        if "detections/" not in path_str:
            return False
        return not self._is_in_excluded_dir(
            file_path, {"tests", "test", "deprecated", ".git"}
        )

    def parse(self, file_path: Path, content: str) -> Optional[ParsedRule]:
        try:
            # Take the first doc (some files have a second `correlation:`
            # doc as a Sigma cross-rule reference; ignore it).
            data = list(yaml.safe_load_all(content))
            if not data:
                return None
            rule = data[0]

            validated = self._validate_rule_shape(rule, file_path, "title", "detection")
            if validated is None:
                return None
            title, detection = validated

            logsource = rule.get("logsource") or {}
            tags = rule.get("tags") or []

            # Reuse the Sigma parser's tag-based MITRE extractor --
            # Auth0 rules use the identical `attack.t<id>` convention.
            mitre_attack = _SIGMA._extract_mitre_from_tags(tags)
            non_mitre_tags = [t for t in tags if not _SIGMA._is_mitre_tag(t)]

            false_positives = rule.get("falsepositives") or []
            if not isinstance(false_positives, list):
                false_positives = [false_positives] if false_positives else []

            return ParsedRule(
                source=self.source_name,
                file_path=str(file_path),
                raw_content=content,
                title=title,
                description=rule.get("description"),
                author=rule.get("author"),
                status=rule.get("status", "stable"),
                severity=rule.get("level", "unknown"),
                log_source={
                    "product": logsource.get("product"),
                    "category": logsource.get("category"),
                    "service": logsource.get("service"),
                },
                tags=non_mitre_tags,
                mitre_attack=mitre_attack,
                detection_logic_raw=detection,
                false_positives=false_positives,
                extra={
                    "id": rule.get("id"),
                    "date": rule.get("date"),
                    "modified": rule.get("modified"),
                    # Auth0-specific siblings -- captured so the rule
                    # detail UI can surface them. Not used by the
                    # canonical resolver (which keys off logsource).
                    "splunk_query": rule.get("splunk"),
                    "tenant_logs_query": rule.get("tenant_logs"),
                    "prevention": rule.get("prevention") or [],
                    "comments": rule.get("comments") or [],
                    "explanation": rule.get("explanation"),
                    "references": rule.get("references") or [],
                },
            )

        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None
