"""
Log Source Taxonomy Service

Provides a unified taxonomy for standardizing log sources across different
detection rule vendors (Sigma, Elastic, Splunk, etc.).

Taxonomy Structure:
- Platform: Specific products/technologies that generate logs
- Event Category: The type of telemetry/activity being monitored
- Data Source: The specific log source or collection method
"""

from typing import Optional, Tuple, List


# =============================================================================
# PLATFORM TAXONOMY
# Organized by technology category - specific products that generate logs
# =============================================================================

PLATFORMS = {
    # Endpoint Operating Systems
    "windows": {
        "display_name": "Windows",
        "category": "endpoint",
        "keywords": [
            "windows", "win", "winlogbeat", "sysmon", "microsoft-windows",
            "powershell", "cmd", "wmi", "msiexec", "certutil", "regsvr32",
            "wscript", "cscript", "mshta", "rundll32", "bits"
        ]
    },
    "linux": {
        "display_name": "Linux",
        "category": "endpoint",
        "keywords": [
            "linux", "unix", "auditd", "syslog", "systemd", "journald",
            "bash", "cron", "ssh", "sudo", "apt", "yum", "rpm", "deb",
            "iptables", "selinux", "apparmor"
        ]
    },
    "macos": {
        "display_name": "macOS",
        "category": "endpoint",
        "keywords": [
            "macos", "mac", "osx", "apple", "darwin", "unified_log",
            "launchd", "spotlight", "gatekeeper", "xprotect"
        ]
    },

    # Cloud Providers (IaaS/PaaS)
    "aws": {
        "display_name": "AWS",
        "category": "cloud",
        "keywords": [
            "aws", "amazon", "cloudtrail", "cloudwatch", "guardduty",
            "s3", "ec2", "iam", "lambda", "eks", "ecs", "rds", "vpc"
        ]
    },
    "azure": {
        "display_name": "Azure",
        "category": "cloud",
        "keywords": [
            "azure", "microsoft-azure", "azure_activity", "azure_monitor",
            "azure_sentinel", "entra", "aad", "azure_ad", "azure_storage",
            "azure_vm", "azure_keyvault", "azure_network"
        ]
    },
    "gcp": {
        "display_name": "Google Cloud",
        "category": "cloud",
        "keywords": [
            "gcp", "google_cloud", "google-cloud", "gcp_audit",
            "gce", "gke", "bigquery", "gcs", "cloud_functions"
        ]
    },

    # SaaS - Identity & Access
    "microsoft_365": {
        "display_name": "Microsoft 365",
        "category": "saas",
        "keywords": [
            "o365", "office365", "m365", "microsoft_365", "microsoft365",
            "sharepoint", "onedrive", "teams", "exchange_online",
            "defender_365", "microsoft_defender"
        ]
    },
    "okta": {
        "display_name": "Okta",
        "category": "saas",
        "keywords": [
            "okta", "okta_system", "okta_auth", "okta_sso"
        ]
    },
    "google_workspace": {
        "display_name": "Google Workspace",
        "category": "saas",
        "keywords": [
            "google_workspace", "gsuite", "g_suite", "gmail", "google_drive",
            "google_admin", "google_meet"
        ]
    },
    "duo": {
        "display_name": "Cisco Duo",
        "category": "saas",
        "keywords": [
            "duo", "cisco_duo", "duo_security", "duo_mfa"
        ]
    },
    "onelogin": {
        "display_name": "OneLogin",
        "category": "saas",
        "keywords": [
            "onelogin", "one_login"
        ]
    },
    "auth0": {
        "display_name": "Auth0",
        "category": "saas",
        "keywords": [
            "auth0"
        ]
    },

    # SaaS - Other
    "github": {
        "display_name": "GitHub",
        "category": "saas",
        "keywords": [
            "github", "github_audit", "github_actions"
        ]
    },
    "salesforce": {
        "display_name": "Salesforce",
        "category": "saas",
        "keywords": [
            "salesforce", "sfdc"
        ]
    },
    "slack": {
        "display_name": "Slack",
        "category": "saas",
        "keywords": [
            "slack", "slack_audit"
        ]
    },
    "zoom": {
        "display_name": "Zoom",
        "category": "saas",
        "keywords": [
            "zoom", "zoom_meeting"
        ]
    },

    # Network Security - Firewalls
    "palo_alto": {
        "display_name": "Palo Alto",
        "category": "network",
        "keywords": [
            "paloalto", "palo_alto", "pan", "pan-os", "panw",
            "palo_alto_networks", "prisma"
        ]
    },
    "fortigate": {
        "display_name": "FortiGate",
        "category": "network",
        "keywords": [
            "fortinet", "fortigate", "forti", "fortios", "fortianalyzer"
        ]
    },
    "cisco_asa": {
        "display_name": "Cisco ASA",
        "category": "network",
        "keywords": [
            "cisco_asa", "asa", "cisco_firewall", "cisco_ftd"
        ]
    },
    "checkpoint": {
        "display_name": "Check Point",
        "category": "network",
        "keywords": [
            "checkpoint", "check_point", "smartconsole"
        ]
    },

    # Network Security - Proxy/Web Gateway
    "zscaler": {
        "display_name": "Zscaler",
        "category": "network",
        "keywords": [
            "zscaler", "zia", "zpa", "zscaler_internet_access"
        ]
    },
    "cisco_umbrella": {
        "display_name": "Cisco Umbrella",
        "category": "network",
        "keywords": [
            "umbrella", "cisco_umbrella", "opendns"
        ]
    },
    "bluecoat": {
        "display_name": "Symantec ProxySG",
        "category": "network",
        "keywords": [
            "bluecoat", "proxysg", "symantec_proxy"
        ]
    },

    # Network Security - IDS/IPS
    "suricata": {
        "display_name": "Suricata",
        "category": "network",
        "keywords": [
            "suricata", "suricata_ids"
        ]
    },
    "snort": {
        "display_name": "Snort",
        "category": "network",
        "keywords": [
            "snort", "snort_ids"
        ]
    },
    "zeek": {
        "display_name": "Zeek",
        "category": "network",
        "keywords": [
            "zeek", "bro", "zeek_logs"
        ]
    },

    # Email Security
    "exchange": {
        "display_name": "Microsoft Exchange",
        "category": "email",
        "keywords": [
            "exchange", "microsoft_exchange", "exchange_server",
            "exchange_online", "owa"
        ]
    },
    "proofpoint": {
        "display_name": "Proofpoint",
        "category": "email",
        "keywords": [
            "proofpoint", "proofpoint_tap", "proofpoint_pod"
        ]
    },
    "mimecast": {
        "display_name": "Mimecast",
        "category": "email",
        "keywords": [
            "mimecast"
        ]
    },

    # EDR/XDR
    "crowdstrike": {
        "display_name": "CrowdStrike",
        "category": "edr",
        "keywords": [
            "crowdstrike", "falcon", "cs_falcon", "crowdstrike_falcon"
        ]
    },
    "defender_endpoint": {
        "display_name": "Defender for Endpoint",
        "category": "edr",
        "keywords": [
            "mde", "wdatp", "defender", "microsoft_defender",
            "defender_for_endpoint", "microsoft_defender_endpoint"
        ]
    },
    "sentinelone": {
        "display_name": "SentinelOne",
        "category": "edr",
        "keywords": [
            "sentinelone", "s1", "sentinel_one"
        ]
    },
    "carbon_black": {
        "display_name": "Carbon Black",
        "category": "edr",
        "keywords": [
            "carbon_black", "carbonblack", "cb", "vmware_carbon_black"
        ]
    },

    # Container/Kubernetes
    "kubernetes": {
        "display_name": "Kubernetes",
        "category": "container",
        "keywords": [
            "kubernetes", "k8s", "kubectl", "kube", "eks", "aks", "gke"
        ]
    },
    "docker": {
        "display_name": "Docker",
        "category": "container",
        "keywords": [
            "docker", "container", "containerd"
        ]
    },
}

# Reverse lookup: keyword -> platform
PLATFORM_KEYWORD_MAP = {}
for platform_id, info in PLATFORMS.items():
    for keyword in info["keywords"]:
        PLATFORM_KEYWORD_MAP[keyword.lower()] = platform_id


# =============================================================================
# EVENT CATEGORY TAXONOMY
# Types of telemetry/events - what kind of activity is being monitored
# These are NOT MITRE tactics - they describe the type of log/telemetry
# =============================================================================

EVENT_CATEGORIES = {
    # Endpoint Events
    "process": {
        "display_name": "Process Activity",
        "description": "Process creation, termination, and injection events",
        "keywords": [
            "process_creation", "process_access", "process_termination",
            "process_start", "process_stop", "create_process",
            "image_load", "driver_load", "process_injection",
            "create_remote_thread", "sysmon_event_1", "sysmon_event_7",
            "sysmon_event_8", "eventid_4688"
        ]
    },
    "file": {
        "display_name": "File Activity",
        "description": "File creation, modification, deletion, and access events",
        "keywords": [
            "file_event", "file_creation", "file_modification", "file_delete",
            "file_access", "file_change", "file_rename", "file_write",
            "file_read", "file_open", "sysmon_event_11", "sysmon_event_23",
            "create_stream_hash", "alternate_data_stream"
        ]
    },
    "network_connection": {
        "display_name": "Network Connections",
        "description": "TCP/UDP connections, socket operations",
        "keywords": [
            "network_connection", "socket", "tcp", "udp",
            "sysmon_event_3", "connection_attempt", "established_connection"
        ]
    },
    "dns": {
        "display_name": "DNS Activity",
        "description": "DNS queries, responses, and resolution events",
        "keywords": [
            "dns_query", "dns_event", "dns_request", "dns_response",
            "sysmon_event_22", "dns_lookup", "name_resolution"
        ]
    },
    "http": {
        "display_name": "Web/HTTP Traffic",
        "description": "HTTP requests, web traffic, proxy logs",
        "keywords": [
            "http", "https", "web", "proxy", "web_proxy", "url",
            "user_agent", "web_request"
        ]
    },
    "firewall": {
        "display_name": "Firewall Events",
        "description": "Firewall allow/deny, traffic flow events",
        "keywords": [
            "firewall", "fw", "firewall_allow", "firewall_deny",
            "traffic_flow", "blocked", "permitted"
        ]
    },
    "registry": {
        "display_name": "Registry Activity",
        "description": "Windows registry key and value modifications",
        "keywords": [
            "registry_event", "registry_add", "registry_delete", "registry_set",
            "registry_value", "registry_key", "sysmon_event_12",
            "sysmon_event_13", "sysmon_event_14", "regkey", "regvalue"
        ]
    },
    "authentication": {
        "display_name": "Authentication",
        "description": "Login, logout, MFA, and credential events",
        "keywords": [
            "logon", "logoff", "authentication", "failed_logon", "login",
            "logout", "credential", "session", "token", "kerberos",
            "ntlm", "ldap_bind", "mfa", "password", "eventid_4624",
            "eventid_4625", "eventid_4648"
        ]
    },
    "api_activity": {
        "display_name": "API Activity",
        "description": "Cloud API calls, management operations",
        "keywords": [
            "api", "api_call", "management_event", "control_plane",
            "admin_activity", "cloudtrail", "audit_log"
        ]
    },
    "email": {
        "display_name": "Email Events",
        "description": "Email send, receive, attachments, link clicks",
        "keywords": [
            "email", "mail", "smtp", "message_trace", "email_received",
            "email_sent", "attachment", "phishing", "spam"
        ]
    },
    "identity_management": {
        "display_name": "Identity Management",
        "description": "User/group creation, role changes, permissions",
        "keywords": [
            "user_created", "user_deleted", "group_membership",
            "role_assignment", "permission_change", "privilege_change",
            "identity", "iam"
        ]
    },
    "configuration_change": {
        "display_name": "Configuration Changes",
        "description": "System, application, and policy configuration changes",
        "keywords": [
            "config_change", "policy_change", "setting_change",
            "configuration", "audit_policy", "system_config"
        ]
    },
    "scheduled_task": {
        "display_name": "Scheduled Tasks",
        "description": "Scheduled task and cron job events",
        "keywords": [
            "scheduled_task", "cron", "at_job", "task_scheduler",
            "schtasks", "launchd"
        ]
    },
    "service": {
        "display_name": "Service Events",
        "description": "Service installation, start, stop events",
        "keywords": [
            "service_install", "service_start", "service_stop",
            "service_created", "sysmon_event_6", "systemd_service"
        ]
    },
    "pipe": {
        "display_name": "Named Pipes",
        "description": "Named pipe creation and connection events",
        "keywords": [
            "pipe_created", "pipe_connected", "named_pipe",
            "sysmon_event_17", "sysmon_event_18"
        ]
    },
    "wmi": {
        "display_name": "WMI Events",
        "description": "WMI activity and event subscriptions",
        "keywords": [
            "wmi", "wmi_event", "sysmon_event_19", "sysmon_event_20",
            "sysmon_event_21", "wmi_filter", "wmi_consumer"
        ]
    },
}

# Reverse lookup: keyword -> event_category
EVENT_CATEGORY_KEYWORD_MAP = {}
for category_id, info in EVENT_CATEGORIES.items():
    for keyword in info["keywords"]:
        EVENT_CATEGORY_KEYWORD_MAP[keyword.lower()] = category_id


# =============================================================================
# DATA SOURCE MAPPING
# Specific log sources with known platform and category associations
# =============================================================================

DATA_SOURCES = {
    # Windows
    "sysmon": {
        "platform": "windows",
        "categories": ["process", "file", "network_connection", "dns", "registry", "pipe", "wmi"],
        "display_name": "Sysmon"
    },
    "security": {
        "platform": "windows",
        "categories": ["authentication", "process", "identity_management"],
        "display_name": "Windows Security Log"
    },
    "powershell": {
        "platform": "windows",
        "categories": ["process"],
        "display_name": "PowerShell"
    },
    "winlogbeat": {
        "platform": "windows",
        "categories": ["process", "authentication", "file"],
        "display_name": "Winlogbeat"
    },

    # Linux
    "auditd": {
        "platform": "linux",
        "categories": ["process", "file", "authentication"],
        "display_name": "Linux Auditd"
    },
    "syslog": {
        "platform": "linux",
        "categories": ["authentication", "process", "network_connection"],
        "display_name": "Syslog"
    },

    # Cloud
    "cloudtrail": {
        "platform": "aws",
        "categories": ["api_activity", "authentication", "identity_management"],
        "display_name": "AWS CloudTrail"
    },
    "azure_activity": {
        "platform": "azure",
        "categories": ["api_activity", "authentication", "identity_management"],
        "display_name": "Azure Activity Log"
    },
    "gcp_audit": {
        "platform": "gcp",
        "categories": ["api_activity", "authentication"],
        "display_name": "GCP Audit Logs"
    },

    # Network
    "zeek_conn": {
        "platform": "zeek",
        "categories": ["network_connection"],
        "display_name": "Zeek Connection Logs"
    },
    "zeek_dns": {
        "platform": "zeek",
        "categories": ["dns"],
        "display_name": "Zeek DNS Logs"
    },
    "zeek_http": {
        "platform": "zeek",
        "categories": ["http"],
        "display_name": "Zeek HTTP Logs"
    },
}


# =============================================================================
# STANDARDIZATION FUNCTIONS
# =============================================================================

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
    # Combine all input into searchable text
    search_parts = [
        " ".join(log_sources),
        product or "",
        category or "",
        service or "",
        " ".join(index_patterns or [])
    ]
    search_text = " ".join(search_parts).lower()

    # Detect platform
    platform = _detect_platform(search_text, product, service, index_patterns)

    # Detect event category
    event_category = _detect_event_category(search_text, category)

    # Detect data source
    data_source = _detect_data_source(search_text, service, index_patterns)

    return platform, event_category, data_source


def _detect_platform(
    search_text: str,
    product: Optional[str] = None,
    service: Optional[str] = None,
    index_patterns: Optional[List[str]] = None
) -> str:
    """Detect the platform from search text and hints."""

    # Check product hint first (most reliable)
    if product:
        product_lower = product.lower().replace("-", "_").replace(" ", "_")
        if product_lower in PLATFORM_KEYWORD_MAP:
            return PLATFORM_KEYWORD_MAP[product_lower]
        # Check if product matches a platform key directly
        if product_lower in PLATFORMS:
            return product_lower

    # Check service for known data sources
    if service:
        service_lower = service.lower()
        if service_lower in DATA_SOURCES:
            return DATA_SOURCES[service_lower]["platform"]

    # Check index patterns for clues
    if index_patterns:
        for pattern in index_patterns:
            pattern_lower = pattern.lower()
            for keyword, platform in PLATFORM_KEYWORD_MAP.items():
                if keyword in pattern_lower:
                    return platform

    # Score-based detection from search text
    scores = {}
    for platform_id, info in PLATFORMS.items():
        score = 0
        for keyword in info["keywords"]:
            if keyword in search_text:
                score += 1
        if score > 0:
            scores[platform_id] = score

    if scores:
        return max(scores, key=scores.get)

    return ""


def _detect_event_category(search_text: str, category: Optional[str] = None) -> str:
    """Detect the event category from search text and category hint."""

    # Check category hint first
    if category:
        category_lower = category.lower().replace("-", "_").replace(" ", "_")
        if category_lower in EVENT_CATEGORY_KEYWORD_MAP:
            return EVENT_CATEGORY_KEYWORD_MAP[category_lower]
        # Check if category matches a category key directly
        if category_lower in EVENT_CATEGORIES:
            return category_lower

    # Score-based detection from search text
    scores = {}
    for category_id, info in EVENT_CATEGORIES.items():
        score = 0
        for keyword in info["keywords"]:
            if keyword in search_text:
                score += 1
        if score > 0:
            scores[category_id] = score

    if scores:
        return max(scores, key=scores.get)

    return ""


def _detect_data_source(
    search_text: str,
    service: Optional[str] = None,
    index_patterns: Optional[List[str]] = None
) -> str:
    """Detect the specific data source."""

    # Check service mapping first
    if service:
        service_lower = service.lower()
        if service_lower in DATA_SOURCES:
            return service_lower

    # Check index patterns
    if index_patterns:
        for pattern in index_patterns:
            pattern_lower = pattern.lower()
            for source_name in DATA_SOURCES:
                if source_name in pattern_lower:
                    return source_name

    # Check search text for known data sources
    for source_name in DATA_SOURCES:
        if source_name in search_text:
            return source_name

    return ""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_platform_display_name(platform: str) -> str:
    """Get display name for a platform."""
    if platform in PLATFORMS:
        return PLATFORMS[platform]["display_name"]
    return platform.replace("_", " ").title() if platform else "Unknown"


def get_platform_category(platform: str) -> str:
    """Get the category for a platform (endpoint, cloud, saas, network, etc.)."""
    if platform in PLATFORMS:
        return PLATFORMS[platform]["category"]
    return ""


def get_event_category_display_name(category: str) -> str:
    """Get display name for an event category."""
    if category in EVENT_CATEGORIES:
        return EVENT_CATEGORIES[category]["display_name"]
    return category.replace("_", " ").title() if category else "Unknown"


def get_all_platforms() -> List[str]:
    """Get list of all valid platform IDs."""
    return list(PLATFORMS.keys())


def get_all_platform_categories() -> List[str]:
    """Get list of unique platform categories."""
    return list(set(p["category"] for p in PLATFORMS.values()))


def get_platforms_by_category(category: str) -> List[str]:
    """Get platforms in a specific category (e.g., 'cloud', 'network')."""
    return [
        platform_id
        for platform_id, info in PLATFORMS.items()
        if info["category"] == category
    ]


def get_all_event_categories() -> List[str]:
    """Get list of all valid event category IDs."""
    return list(EVENT_CATEGORIES.keys())


def get_all_data_sources() -> List[str]:
    """Get list of all known data source IDs."""
    return list(DATA_SOURCES.keys())
