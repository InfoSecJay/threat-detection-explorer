"""Base normalizer interface for detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import hashlib
import uuid

from app.parsers.base import ParsedRule
from app.services.git_service import GitService
from app.services.log_source_taxonomy import standardize_log_sources

# Namespace for deterministic detection ids (#86). NEVER change: every
# permalink derives from it.
_PERMALINK_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://detectionexplorer.io")


@dataclass
class NormalizedDetection:
    """Normalized detection rule ready for storage.

    This is the final normalized format that all vendors map to.
    """

    # Unique identifier (deterministic based on source + file path)
    id: str

    # Source information
    source: str
    source_file: str
    source_repo_url: str

    # Core metadata (required fields)
    title: str
    description: Optional[str]
    author: Optional[str]

    # Status: stable, test, experimental, deprecated, unsupported, unknown
    # (Sigma vocabulary 1:1 -- see normalize_status, issue #26)
    status: str

    # Severity: low, medium, high, critical, unknown
    severity: str

    # Fields with defaults must come after required fields
    source_rule_url: Optional[str] = None  # Direct link to rule in source repo
    # Building-block / signal-only rule (issue #26): emits signal for
    # other rules to correlate on instead of alerting by itself.
    # Orthogonal to status (a building block can be stable). Set by
    # the Elastic and Panther/pypanther normalizers; False elsewhere.
    is_building_block: bool = False
    # HOW the rule works (#105 / teardown R06): rule | hunting | ml_job |
    # correlation | indicator_match | building_block. Normalizers set
    # it from the vendor's rule-type field where one exists; otherwise
    # __post_init__ lifts it from the modality markers in event_types
    # and from is_building_block. See canonical.RULE_MODALITIES.
    rule_modality: str = "rule"
    rule_id: Optional[str] = None  # Original rule ID from source

    # MITRE ATT&CK
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    # ATT&CK Group + Software IDs (verbatim: "G0016", "S0002"). Display
    # names resolved on read via app.services.mitre_lookup. Populated
    # for sources with `attack.g*` / `attack.s*` tag conventions;
    # empty elsewhere.
    mitre_groups: list[str] = field(default_factory=list)
    mitre_software: list[str] = field(default_factory=list)

    # Human-readable detection logic summary
    detection_logic: str = ""

    # Rule language/format (e.g., sigma, eql, esql, spl, mql)
    language: str = "unknown"

    # Tags
    tags: list[str] = field(default_factory=list)

    # References (external links, CVEs, documentation)
    references: list[str] = field(default_factory=list)

    # False positives / known limitations
    false_positives: list[str] = field(default_factory=list)

    # Vendor-authored investigation guide (markdown), when the format
    # carries one (Elastic `note`). None otherwise.
    investigation_guide: Optional[str] = None

    # Original raw content
    raw_content: str = ""

    # Extracted observable fields (from detection logic parsing)
    extracted_fields_used: list[str] = field(default_factory=list)
    extracted_event_ids: list[str] = field(default_factory=list)
    extracted_process_names: list[str] = field(default_factory=list)
    extracted_file_paths: list[str] = field(default_factory=list)
    extracted_registry_keys: list[str] = field(default_factory=list)
    extracted_network_indicators: list[str] = field(default_factory=list)
    extracted_source_tables: list[str] = field(default_factory=list)
    extracted_observables: list[dict] = field(default_factory=list)
    query_complexity: str = "unknown"
    extracted_api_actions: list[str] = field(default_factory=list)
    extracted_target_resources: list[str] = field(default_factory=list)

    # Rule dates from source
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None
    # Last touches of the rule file upstream, newest first (#127):
    # [{sha, author, date, subject}], capped at 10 by the git service.
    upstream_history: list[dict] = field(default_factory=list)

    # ── Canonical taxonomy fields ────────────────────────────────────────
    # Populated by `BaseNormalizer._resolve_taxonomy()`. See
    # `app/services/taxonomy/` for the resolver and mapping files.
    # Phase 3 dropped the legacy single-value siblings (platform,
    # event_category, data_source_normalized) and the raw vendor
    # lists (log_sources, raw data_sources) -- these three lists are
    # now the only taxonomy on the model.
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)

    # Vendor-preserved analytic story / use-case labels. Populated for
    # sources with an explicit story/use-case concept (Splunk, Elastic,
    # Sublime); empty list on other sources.
    use_cases: list[str] = field(default_factory=list)

    # Coverage signal — True if the resolver found a mapping, False if
    # we fell through to [UNKNOWN] for every dimension. Feeds per-sync
    # coverage metrics + drift notifications. Not persisted to the DB
    # (yet); lives on the per-sync stats and sync_job.repository_results.
    taxonomy_matched: bool = False
    # Stable signature of the rule's logsource input — groups identical
    # unmapped rules in drift reports.
    taxonomy_fingerprint: str = ""
    # The v1 path-hash id (sha256 of source:file_path). Kept so ingest
    # can write a legacy alias for links shared before the
    # deterministic-id migration (#86). Set in __post_init__.
    legacy_id: str = ""

    def __post_init__(self) -> None:
        # Deterministic permalinks (#86 / teardown F10): when the
        # upstream publishes a rule id, the canonical id is a UUIDv5
        # over (source, rule_id) — stable across file moves, renames
        # and full rebuilds. The path-hash id becomes `legacy_id` and
        # is written to the alias table so old links 301. Rules without
        # an upstream id keep the path hash (nothing better exists).
        # Upstream duplicate rule_ids are detected at ingest time and
        # fall back to the path hash there.
        self.legacy_id = self.id
        rid = (self.rule_id or "").strip() if isinstance(self.rule_id, str) else ""
        if rid:
            self.id = str(uuid.uuid5(_PERMALINK_NAMESPACE, f"{self.source}:{rid}"))

        # Second-pass taxonomy refinement (issue #16): a coarse
        # `audit_event` from a channel-level logsource is replaced by
        # what the rule's own event IDs say (4624 -> authentication,
        # 4688 -> process_creation, ...). Lives here rather than in each
        # normalizer so every source -- present and future -- gets it,
        # and because this is the one place that has BOTH the resolved
        # taxonomy and the extracted event IDs. Pure function; see
        # `app/services/taxonomy/event_ids.py` for the rules.
        from app.services.taxonomy.event_ids import namespace_event_ids, refine_event_types

        # Channel-namespace the IDs first (teardown R12 / #110):
        # `sysmon:1` vs `security:4688`, decided from the rule's
        # canonical data source. Refinement below is prefix-aware.
        self.extracted_event_ids = namespace_event_ids(
            self.extracted_event_ids,
            self.platforms,
            self.data_sources,
        )
        self.event_types = refine_event_types(
            self.event_types,
            self.platforms,
            self.data_sources,
            self.extracted_event_ids,
        )

        # Lift modality markers out of event_types (#105): the mapping
        # files may say `hunting_query` / `ml_detection` /
        # `alert_correlation` for a logsource, but those describe how
        # the rule works, not what it observes. A normalizer's explicit
        # modality wins; the marker only fills the default.
        from app.services.taxonomy.canonical import (
            EVENT_TYPE_MODALITY_LIFT,
            RULE_MODALITIES,
        )

        lifted = [EVENT_TYPE_MODALITY_LIFT[t] for t in self.event_types if t in EVENT_TYPE_MODALITY_LIFT]
        self.event_types = [t for t in self.event_types if t not in EVENT_TYPE_MODALITY_LIFT]
        if self.rule_modality not in RULE_MODALITIES:
            self.rule_modality = "rule"
        if self.rule_modality == "rule":
            if lifted:
                self.rule_modality = lifted[0]
            elif self.is_building_block:
                self.rule_modality = "building_block"
        if not self.event_types:
            self.event_types = ["unknown"]


class BaseNormalizer(ABC):
    """Abstract base class for detection rule normalizers."""

    def __init__(self, repo_url: str, repo_path: Optional[Path] = None):
        """Initialize normalizer with repository URL and optional local clone path.

        Args:
            repo_url: Base URL for the source repository
            repo_path: Local path to the cloned repository. When provided, the
                normalizer can fall back to `git log` for rule creation/modified
                dates when the source rule file doesn't embed them. Optional so
                tests and legacy callers still work without a clone on disk.
        """
        self.repo_url = repo_url
        self.repo_path = repo_path
        self._git_service: Optional[GitService] = (
            GitService(repo_path) if repo_path else None
        )

    def prepare_git_history(self) -> int:
        """Build the per-repo git index once before an ingest (#132).

        Dates and history for every rule then come from one `git log`
        walk instead of three subprocesses per file. Returns the number
        of indexed paths; 0 when there is no clone (tests) or the walk
        failed, in which case lookups fall back to the per-file calls.
        """
        if self._git_service is None:
            return 0
        try:
            return self._git_service.build_index()
        except Exception:  # noqa: BLE001 -- history is decoration, not data
            return 0

    def _resolve_taxonomy(
        self, parsed: ParsedRule
    ) -> tuple[list[str], list[str], list[str], bool, str]:
        """Resolve canonical taxonomy + coverage signal for a parsed rule.

        Delegates to `app.services.taxonomy.resolve_for_repo` using the
        repo name carried on the parsed rule. Subclasses call this once
        in `normalize()` and pass the result into `NormalizedDetection`.

        Returns a 5-tuple:
          (platforms, data_sources, event_types, matched, fingerprint)

        The first three lists always contain at least `["unknown"]` if
        the vendor data didn't supply enough info, so this method never
        raises and never returns empty lists. `matched` is True iff ANY
        of the three dimensions got a non-empty value from vendor data
        (before the UNKNOWN fallback). `fingerprint` is a stable short
        string identifying the rule's logsource signature, used to group
        unmapped rules in drift reports.
        """
        # Lazy import: keeps the taxonomy package out of the import chain
        # until first use, and avoids any circular-import surprises.
        from app.services.taxonomy import resolve_for_repo

        result = resolve_for_repo(parsed.source, parsed)
        return (
            result["platforms"],
            result["data_sources"],
            result["event_types"],
            result["matched"],
            result["fingerprint"],
        )

    def _resolve_rule_dates(
        self,
        file_path: str,
        embedded_created: Optional[datetime] = None,
        embedded_modified: Optional[datetime] = None,
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """Return (created_date, modified_date), preferring embedded values.

        If the rule file embeds a date field (Sigma `date`/`modified`,
        Splunk `date`, LOLRMM `date`/`modified`), those win — the author's
        stated date is more meaningful than a commit timestamp. Only fields
        left as None fall through to `git log` via the GitService, which
        itself returns None on shallow clones or any other failure.

        Passing `file_path` as the ParsedRule.file_path (repo-relative) lets
        the git service run `git log -- <path>` from the repo root.
        """
        created = embedded_created
        modified = embedded_modified

        if created is None and modified is None and self._git_service is None:
            return None, None

        if self._git_service is not None and (created is None or modified is None):
            git_created, git_modified = self._git_service.get_file_dates(file_path)
            if created is None:
                created = git_created
            if modified is None:
                modified = git_modified

        return created, modified

    def attach_upstream_history(self, normalized: NormalizedDetection, file_path: str) -> None:
        """Fill `upstream_history` from git for every source (#127).

        Runs after `normalize()` so vendor normalizers stay untouched.
        Best-effort: no git service (tests, missing clone) or a shallow
        clone leaves the list empty, never raises.
        """
        if self._git_service is None or not file_path:
            normalized.upstream_history = []
            return
        try:
            normalized.upstream_history = self._git_service.get_file_history(file_path, limit=10)
        except Exception:  # noqa: BLE001 -- history is decoration, not data
            normalized.upstream_history = []

    @abstractmethod
    def normalize(self, parsed: ParsedRule) -> NormalizedDetection:
        """Convert a parsed rule to normalized format.

        Args:
            parsed: ParsedRule from vendor-specific parser

        Returns:
            NormalizedDetection in common schema
        """
        pass

    def generate_id(self, source: str, file_path: str) -> str:
        """Generate a deterministic unique ID for a detection rule.

        Args:
            source: Source vendor name
            file_path: Path to the rule file

        Returns:
            Deterministic UUID-like string
        """
        content = f"{source}:{file_path}"
        hash_bytes = hashlib.sha256(content.encode()).hexdigest()
        # Format as UUID-like string
        return f"{hash_bytes[:8]}-{hash_bytes[8:12]}-{hash_bytes[12:16]}-{hash_bytes[16:20]}-{hash_bytes[20:32]}"

    def normalize_status(self, status: Optional[str]) -> str:
        """Normalize status to standard values.

        Args:
            status: Raw status value

        Returns:
            One of: stable, test, experimental, deprecated, unsupported,
            unknown. The vocabulary follows Sigma's `status` field 1:1
            (issue #26) -- `test` ("works, not yet field-proven") is a
            distinct maturity from `experimental` and was previously
            flattened into it, which made 97% of Sigma look
            experimental. `unsupported` is Sigma's "cannot be run on
            current tooling" and is preserved rather than dropped.
        """
        if not status:
            return "unknown"

        status_lower = status.lower()
        if status_lower in ["stable", "production", "released"]:
            return "stable"
        elif status_lower in ["test", "testing"]:
            return "test"
        elif status_lower in ["experimental", "development", "dev"]:
            return "experimental"
        elif status_lower in ["deprecated", "obsolete", "retired"]:
            return "deprecated"
        elif status_lower in ["unsupported"]:
            return "unsupported"
        elif status_lower in ["not_applicable"]:
            # The source has no lifecycle/maturity concept at all --
            # distinct from `unknown`, where the vendor has one but this
            # rule carries no value (teardown R09 / #107).
            return "not_applicable"
        return "unknown"

    def normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity to standard values.

        Args:
            severity: Raw severity value

        Returns:
            One of: low, medium, high, critical, unknown
        """
        if not severity:
            return "unknown"

        severity_lower = severity.lower()
        if severity_lower in ["informational", "info", "low"]:
            return "low"
        elif severity_lower in ["medium", "moderate"]:
            return "medium"
        elif severity_lower in ["high"]:
            return "high"
        elif severity_lower in ["critical", "severe"]:
            return "critical"
        return "unknown"

    def normalize_log_sources(self, log_source: dict) -> list[str]:
        """Extract normalized log source identifiers.

        Args:
            log_source: Vendor-specific log source dict

        Returns:
            List of normalized log source strings
        """
        sources = []

        product = log_source.get("product")
        if product:
            sources.append(product.lower())

        category = log_source.get("category")
        if category:
            sources.append(category.lower())

        service = log_source.get("service")
        if service:
            sources.append(service.lower())

        # Remove duplicates while preserving order
        seen = set()
        return [s for s in sources if not (s in seen or seen.add(s))]

    def parse_date(self, date_value) -> Optional[datetime]:
        """Parse a date value from various formats.

        Args:
            date_value: Date as string, datetime, or date object

        Returns:
            datetime object or None if parsing fails
        """
        if date_value is None:
            return None

        if isinstance(date_value, datetime):
            return date_value

        # Handle date object (not datetime)
        if hasattr(date_value, 'year') and hasattr(date_value, 'month') and hasattr(date_value, 'day'):
            return datetime(date_value.year, date_value.month, date_value.day)

        if isinstance(date_value, str):
            date_str = date_value.strip()
            # Try various date formats
            formats = [
                "%Y-%m-%d",
                "%Y/%m/%d",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y",
                "%m/%d/%Y",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue

        return None

    def build_source_rule_url(self, file_path: str, branch: str = "main") -> str:
        """Build a direct URL to the rule file in the source repository.

        Args:
            file_path: Relative path to the rule file
            branch: Git branch name (default: main)

        Returns:
            Full URL to view the rule file
        """
        # Ensure consistent path separators
        file_path = file_path.replace("\\", "/")

        # Remove leading slash if present
        if file_path.startswith("/"):
            file_path = file_path[1:]

        # Strip .git suffix from repo URL if present
        repo_url = self.repo_url
        if repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        # Build the GitHub URL
        return f"{repo_url}/blob/{branch}/{file_path}"

    def normalize_references(self, references) -> list[str]:
        """Normalize references to a list of strings.

        Args:
            references: References as list, string, or None

        Returns:
            List of reference strings
        """
        if references is None:
            return []

        if isinstance(references, str):
            return [references] if references.strip() else []

        if isinstance(references, list):
            return [str(ref) for ref in references if ref]

        return []

    def normalize_false_positives(self, false_positives) -> list[str]:
        """Normalize false positives to a list of strings.

        Args:
            false_positives: False positives as list, string, or None

        Returns:
            List of false positive strings
        """
        if false_positives is None:
            return []

        if isinstance(false_positives, str):
            # Single string - return as list if not empty
            fp = false_positives.strip()
            return [fp] if fp else []

        if isinstance(false_positives, list):
            result = []
            for fp in false_positives:
                if fp and isinstance(fp, str):
                    cleaned = fp.strip()
                    if cleaned:
                        result.append(cleaned)
            return result

        return []

    def apply_log_source_taxonomy(
        self,
        log_sources: list[str],
        product: Optional[str] = None,
        category: Optional[str] = None,
        service: Optional[str] = None,
        index_patterns: Optional[list[str]] = None
    ) -> tuple[str, str, str]:
        """Apply the unified log source taxonomy to get standardized values.

        Args:
            log_sources: Raw log sources list
            product: Sigma-style product (e.g., "windows", "linux")
            category: Sigma-style category (e.g., "process_creation")
            service: Sigma-style service (e.g., "sysmon")
            index_patterns: Elastic-style index patterns (e.g., ["winlogbeat-*"])

        Returns:
            Tuple of (platform, event_category, data_source_normalized)
        """
        return standardize_log_sources(
            log_sources=log_sources,
            product=product,
            category=category,
            service=service,
            index_patterns=index_patterns
        )

    def normalize_data_sources(self, raw_sources: list[str]) -> list[str]:
        """Normalize data sources to standardized categories.

        This maps vendor-specific data source names to consistent categories
        for cross-vendor comparison.

        Args:
            raw_sources: List of raw data source strings

        Returns:
            List of normalized data source categories
        """
        # Mapping of patterns to standardized data source names
        data_source_mapping = {
            # Windows Event Logs
            "sysmon": "Sysmon",
            "security": "Windows Security",
            "security_event": "Windows Security",
            "wineventlog": "Windows Event Log",
            "windows_event": "Windows Event Log",
            "system_event": "Windows System",
            "powershell": "PowerShell",
            "powershell_script": "PowerShell Script Block",
            "wmi": "WMI",
            "registry": "Windows Registry",
            "file_monitoring": "File Monitoring",
            "process_creation": "Process Creation",
            "network_connection": "Network Connection",
            "dns": "DNS",
            "dns_query": "DNS",
            "image_load": "Image Load",
            "driver_load": "Driver Load",
            "pipe_created": "Named Pipe",
            "firewall": "Windows Firewall",
            "create_remote_thread": "Remote Thread",
            "process_access": "Process Access",
            "file_event": "File Monitoring",
            "create_stream_hash": "Alternate Data Stream",

            # Endpoint/EDR
            "endpoint": "Endpoint",
            "behavior_event": "Behavior Detection",
            "edr": "EDR",

            # Network
            "network": "Network Traffic",
            "netflow": "NetFlow",
            "packet": "Packet Capture",
            "proxy": "Web Proxy",
            "webproxy": "Web Proxy",
            "firewall_logs": "Firewall",
            "ids": "IDS/IPS",
            "zeek": "Zeek",

            # Cloud
            "aws": "AWS CloudTrail",
            "cloudtrail": "AWS CloudTrail",
            "azure": "Azure Activity",
            "gcp": "GCP Audit",
            "cloud": "Cloud",
            "o365": "Office 365",
            "m365": "Microsoft 365",
            "okta": "Okta",
            "github": "GitHub",

            # Linux/macOS
            "linux_syslog": "Linux Syslog",
            "linux": "Linux",
            "auditd": "Linux Auditd",
            "macos_logs": "macOS Logs",
            "macos": "macOS",
            "unix": "Unix/Linux",

            # Email
            "email": "Email",
            "smtp": "SMTP",

            # Authentication
            "authentication": "Authentication",
            "active_directory": "Active Directory",
            "ldap": "LDAP",

            # RMM specific
            "rmm_tool": "RMM Tool",

            # Web/Application
            "application": "Application",
            "webserver": "Web Server",
            "antivirus": "Antivirus",
        }

        normalized = []
        seen = set()

        for source in raw_sources:
            if not source:
                continue

            source_lower = source.lower().strip()

            # Try exact match first
            if source_lower in data_source_mapping:
                mapped = data_source_mapping[source_lower]
                if mapped not in seen:
                    normalized.append(mapped)
                    seen.add(mapped)
                continue

            # Try partial match
            matched = False
            for pattern, mapped in data_source_mapping.items():
                if pattern in source_lower:
                    if mapped not in seen:
                        normalized.append(mapped)
                        seen.add(mapped)
                    matched = True
                    break

            # If no match, clean up and include as-is
            if not matched:
                # Capitalize words and replace underscores
                clean = source.replace("_", " ").title()
                if clean not in seen:
                    normalized.append(clean)
                    seen.add(clean)

        return normalized
