"""
Log Source Taxonomy Service

Provides a unified taxonomy for standardizing log sources across different
detection rule vendors (Sigma, Elastic, Splunk, etc.).

Taxonomy Structure:
- Platform: The OS or environment (windows, linux, cloud, etc.)
- Event Category: The type of activity being monitored (process, file, network, etc.)
- Data Source: The specific log source or tool (sysmon, auditd, cloudtrail, etc.)
"""

from typing import Optional, Tuple, List, Set


# Platform mappings - keywords that indicate a specific platform
PLATFORM_KEYWORDS: dict[str, list[str]] = {
    "windows": [
        "windows", "win", "winlogbeat", "sysmon", "microsoft",
        "powershell", "cmd", "wmi", "defender", "security",
        "ntlm", "kerberos", "active_directory", "ad", "ldap",
        "mde", "wdatp", "bits", "msiexec", "certutil"
    ],
    "linux": [
        "linux", "unix", "auditd", "syslog", "systemd",
        "bash", "shell", "cron", "ssh", "sudo", "apt", "yum",
        "rpm", "deb", "iptables", "selinux", "apparmor"
    ],
    "macos": [
        "macos", "mac", "osx", "apple", "unified_log",
        "darwin", "launchd", "spotlight", "gatekeeper"
    ],
    "cloud": [
        "aws", "amazon", "azure", "gcp", "google_cloud",
        "cloudtrail", "cloudwatch", "s3", "ec2", "iam",
        "o365", "office365", "m365", "entra", "aad",
        "okta", "onelogin", "duo", "saml", "oauth",
        "kubernetes", "k8s", "docker", "container"
    ],
    "network": [
        "firewall", "proxy", "dns", "zeek", "bro", "suricata",
        "snort", "ids", "ips", "netflow", "pcap", "packet",
        "paloalto", "fortinet", "checkpoint", "cisco"
    ],
    "email": [
        "email", "mail", "smtp", "exchange", "proofpoint",
        "mimecast", "o365_email", "phishing", "spam"
    ],
}

# Event category mappings - activity types
EVENT_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "process": [
        "process_creation", "process_access", "process_termination",
        "process_start", "process_stop", "create_process",
        "image_load", "driver_load", "process_injection"
    ],
    "file": [
        "file_event", "file_creation", "file_modification", "file_delete",
        "file_access", "file_change", "file_rename", "file_write",
        "file_read", "file_open", "sysmon_event_11"
    ],
    "network": [
        "network_connection", "dns_query", "dns_event", "firewall",
        "proxy", "web", "http", "tcp", "udp", "socket",
        "sysmon_event_3", "sysmon_event_22"
    ],
    "registry": [
        "registry_event", "registry_add", "registry_delete", "registry_set",
        "registry_value", "registry_key", "sysmon_event_12",
        "sysmon_event_13", "sysmon_event_14"
    ],
    "authentication": [
        "logon", "logoff", "authentication", "failed_logon", "login",
        "logout", "credential", "session", "token", "kerberos",
        "ntlm", "ldap_bind"
    ],
    "persistence": [
        "scheduled_task", "service_install", "autorun", "startup",
        "registry_run", "cron", "launchd", "systemd_service"
    ],
    "execution": [
        "script_execution", "powershell", "wmi", "command_line",
        "bash", "python", "javascript", "vbscript", "wscript", "cscript"
    ],
    "privilege_escalation": [
        "privilege", "elevation", "sudo", "runas", "impersonation",
        "token_manipulation", "setuid"
    ],
    "discovery": [
        "discovery", "enumeration", "reconnaissance", "scanning",
        "whoami", "systeminfo", "netstat", "ipconfig"
    ],
    "lateral_movement": [
        "lateral", "psexec", "wmic_remote", "rdp", "smb",
        "winrm", "ssh_lateral", "remote_exec"
    ],
}

# Known data sources with their platform and typical categories
DATA_SOURCE_INFO: dict[str, dict] = {
    # Windows sources
    "sysmon": {
        "platform": "windows",
        "categories": ["process", "file", "network", "registry"],
        "aliases": ["sysmon", "microsoft-sysmon"]
    },
    "security": {
        "platform": "windows",
        "categories": ["authentication", "process", "privilege_escalation"],
        "aliases": ["security", "windows_security", "security_log"]
    },
    "powershell": {
        "platform": "windows",
        "categories": ["execution", "process"],
        "aliases": ["powershell", "microsoft-powershell", "ps"]
    },
    "defender": {
        "platform": "windows",
        "categories": ["process", "file", "network"],
        "aliases": ["defender", "microsoft-defender", "mde", "wdatp"]
    },
    "winlogbeat": {
        "platform": "windows",
        "categories": ["process", "authentication", "file"],
        "aliases": ["winlogbeat", "winlog"]
    },

    # Linux sources
    "auditd": {
        "platform": "linux",
        "categories": ["process", "file", "authentication"],
        "aliases": ["auditd", "audit", "linux_audit"]
    },
    "syslog": {
        "platform": "linux",
        "categories": ["authentication", "process", "network"],
        "aliases": ["syslog", "rsyslog", "syslog-ng"]
    },
    "systemd": {
        "platform": "linux",
        "categories": ["persistence", "process"],
        "aliases": ["systemd", "journald", "journal"]
    },

    # Cloud sources
    "cloudtrail": {
        "platform": "cloud",
        "categories": ["authentication", "discovery", "persistence"],
        "aliases": ["cloudtrail", "aws_cloudtrail", "aws"]
    },
    "azure_activity": {
        "platform": "cloud",
        "categories": ["authentication", "discovery"],
        "aliases": ["azure", "azure_activity", "azure_monitor"]
    },
    "gcp_audit": {
        "platform": "cloud",
        "categories": ["authentication", "discovery"],
        "aliases": ["gcp", "google_cloud", "gcp_audit"]
    },
    "okta": {
        "platform": "cloud",
        "categories": ["authentication"],
        "aliases": ["okta", "okta_system"]
    },

    # Network sources
    "zeek": {
        "platform": "network",
        "categories": ["network", "discovery"],
        "aliases": ["zeek", "bro", "zeek_logs"]
    },
    "firewall": {
        "platform": "network",
        "categories": ["network"],
        "aliases": ["firewall", "fw", "paloalto", "fortinet"]
    },
    "proxy": {
        "platform": "network",
        "categories": ["network"],
        "aliases": ["proxy", "web_proxy", "squid", "bluecoat"]
    },

    # Email sources
    "exchange": {
        "platform": "email",
        "categories": ["email"],
        "aliases": ["exchange", "o365_email", "microsoft_exchange"]
    },
    "proofpoint": {
        "platform": "email",
        "categories": ["email"],
        "aliases": ["proofpoint", "proofpoint_tap"]
    },
}


def standardize_log_sources(
    log_sources: List[str],
    product: Optional[str] = None,
    category: Optional[str] = None,
    service: Optional[str] = None,
    index_patterns: Optional[List[str]] = None
) -> Tuple[str, str, str]:
    """
    Standardize log source information into a unified taxonomy.

    Args:
        log_sources: Raw log sources list from normalizer
        product: Sigma-style product (e.g., "windows", "linux")
        category: Sigma-style category (e.g., "process_creation")
        service: Sigma-style service (e.g., "sysmon")
        index_patterns: Elastic-style index patterns (e.g., ["winlogbeat-*"])

    Returns:
        Tuple of (platform, event_category, data_source)
    """
    platform = ""
    event_category = ""
    data_source = ""

    # Combine all input into searchable text
    search_text = " ".join([
        " ".join(log_sources),
        product or "",
        category or "",
        service or "",
        " ".join(index_patterns or [])
    ]).lower()

    # Determine platform
    platform = _detect_platform(search_text, product)

    # Determine event category
    event_category = _detect_event_category(search_text, category)

    # Determine data source
    data_source = _detect_data_source(search_text, service, index_patterns)

    return platform, event_category, data_source


def _detect_platform(search_text: str, product: Optional[str] = None) -> str:
    """Detect the platform from search text and product hint."""
    # Direct product mapping takes priority
    if product:
        product_lower = product.lower()
        for platform, keywords in PLATFORM_KEYWORDS.items():
            if product_lower in keywords or any(kw in product_lower for kw in keywords):
                return platform

    # Search through keywords
    scores: dict[str, int] = {}
    for platform, keywords in PLATFORM_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in search_text)
        if score > 0:
            scores[platform] = score

    if scores:
        return max(scores, key=scores.get)

    return ""


def _detect_event_category(search_text: str, category: Optional[str] = None) -> str:
    """Detect the event category from search text and category hint."""
    # Direct category mapping takes priority
    if category:
        category_lower = category.lower()
        for event_cat, keywords in EVENT_CATEGORY_KEYWORDS.items():
            if category_lower in keywords or any(kw in category_lower for kw in keywords):
                return event_cat

    # Search through keywords
    scores: dict[str, int] = {}
    for event_cat, keywords in EVENT_CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in search_text)
        if score > 0:
            scores[event_cat] = score

    if scores:
        return max(scores, key=scores.get)

    return ""


def _detect_data_source(
    search_text: str,
    service: Optional[str] = None,
    index_patterns: Optional[List[str]] = None
) -> str:
    """Detect the specific data source."""
    # Direct service mapping takes priority
    if service:
        service_lower = service.lower()
        for source_name, info in DATA_SOURCE_INFO.items():
            if service_lower in info["aliases"]:
                return source_name

    # Check index patterns for known sources
    if index_patterns:
        for pattern in index_patterns:
            pattern_lower = pattern.lower()
            for source_name, info in DATA_SOURCE_INFO.items():
                if any(alias in pattern_lower for alias in info["aliases"]):
                    return source_name

    # Search through data source aliases
    for source_name, info in DATA_SOURCE_INFO.items():
        if any(alias in search_text for alias in info["aliases"]):
            return source_name

    return ""


def get_platform_display_name(platform: str) -> str:
    """Get display name for a platform."""
    display_names = {
        "windows": "Windows",
        "linux": "Linux",
        "macos": "macOS",
        "cloud": "Cloud",
        "network": "Network",
        "email": "Email",
    }
    return display_names.get(platform, platform.title() if platform else "Unknown")


def get_category_display_name(category: str) -> str:
    """Get display name for an event category."""
    display_names = {
        "process": "Process Activity",
        "file": "File Activity",
        "network": "Network Activity",
        "registry": "Registry Activity",
        "authentication": "Authentication",
        "persistence": "Persistence",
        "execution": "Execution",
        "privilege_escalation": "Privilege Escalation",
        "discovery": "Discovery",
        "lateral_movement": "Lateral Movement",
    }
    return display_names.get(category, category.replace("_", " ").title() if category else "Unknown")


def get_all_platforms() -> List[str]:
    """Get list of all valid platforms."""
    return list(PLATFORM_KEYWORDS.keys())


def get_all_categories() -> List[str]:
    """Get list of all valid event categories."""
    return list(EVENT_CATEGORY_KEYWORDS.keys())


def get_all_data_sources() -> List[str]:
    """Get list of all known data sources."""
    return list(DATA_SOURCE_INFO.keys())
