"""Base normalizer interface for detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import hashlib

from app.parsers.base import ParsedRule


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

    # Status: stable, experimental, deprecated, unknown
    status: str

    # Severity: low, medium, high, critical, unknown
    severity: str

    # Fields with defaults must come after required fields
    source_rule_url: Optional[str] = None  # Direct link to rule in source repo
    rule_id: Optional[str] = None  # Original rule ID from source

    # Classification
    log_sources: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

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

    # Original raw content
    raw_content: str = ""

    # Rule dates from source
    rule_created_date: Optional[datetime] = None
    rule_modified_date: Optional[datetime] = None


class BaseNormalizer(ABC):
    """Abstract base class for detection rule normalizers."""

    def __init__(self, repo_url: str):
        """Initialize normalizer with repository URL.

        Args:
            repo_url: Base URL for the source repository
        """
        self.repo_url = repo_url

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
            One of: stable, experimental, deprecated, unknown
        """
        if not status:
            return "unknown"

        status_lower = status.lower()
        if status_lower in ["stable", "production", "released"]:
            return "stable"
        elif status_lower in ["experimental", "test", "testing", "development", "dev"]:
            return "experimental"
        elif status_lower in ["deprecated", "obsolete", "retired"]:
            return "deprecated"
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
