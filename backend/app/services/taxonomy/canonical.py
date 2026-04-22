"""Canonical vocabulary for the telemetry-source taxonomy.

This is the SINGLE SOURCE OF TRUTH for which platform/data-source/event-type
identifiers are valid in the normalized fields. Every value written to a
Detection's `taxonomy_platforms`, `taxonomy_data_sources`, or
`taxonomy_event_types` column must come from one of these sets (or be
`UNKNOWN` when the vendor data is missing).

Naming conventions:

- All identifiers are `lowercase_snake_case`. The canonical form is what
  goes into the database and the API JSON response. Display names live
  in the frontend as a separate lookup table (`frontend/src/constants/`).
- Platforms describe WHERE the telemetry comes from (an OS, a cloud, a
  SaaS product, a network appliance class, the email channel).
- Data sources describe WHAT product/integration/feed produces the
  telemetry (Sysmon, AWS CloudTrail, Elastic Defend, etc.).
- Event types describe WHICH activity the rule looks for (process
  creation, network connection, authentication, etc.).

Onboarding a new value:

1. Add it to the appropriate set below with a short comment explaining
   what it covers.
2. Add a mapping entry in the relevant `mappings/<vendor>.yaml` so
   parsed rules can resolve to the new value.
3. Add a display name + color in
   `frontend/src/constants/taxonomy.ts`.
4. Re-run a sync to backfill the column for affected rules.

See docs/taxonomy.md for full guidance.
"""

# Sentinel value used when the vendor data doesn't supply enough info to
# resolve a real canonical value. Lets the frontend filter for "rules with
# unknown <X>" rather than the field being silently empty.
UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# PLATFORMS — where the telemetry runs / lives
# ---------------------------------------------------------------------------

PLATFORMS: frozenset[str] = frozenset(
    {
        # ── Endpoint operating systems ──────────────────────────────────────
        "windows",
        "linux",
        "macos",
        # ── Public cloud platforms ──────────────────────────────────────────
        # Note: `azure` covers ALL Azure services including Entra ID (formerly
        # Azure AD). We used to split them but the distinction is noise — the
        # specific data_source (`entra_id_signin` vs `azure_activity` etc.)
        # gives the precision without needing two platform values.
        "aws",
        "azure",
        "gcp",
        # ── Identity / SaaS productivity platforms ──────────────────────────
        "okta",
        "onelogin",
        "google_workspace",
        "microsoft_365",
        "duo",
        # ── DevOps / source control ─────────────────────────────────────────
        "github",
        "gitlab",
        "bitbucket",
        # ── Network appliance class (broad — covers firewalls, proxies, IDS)
        "network_appliance",
        # ── Email — Sublime and other email-security tooling lives here ─────
        "email",
        # ── Container platforms ─────────────────────────────────────────────
        "kubernetes",
        "docker",
        # ── LLM (Elastic Hunting has rules targeting LLM service logs) ──────
        "llm",
        # ── Cross-platform marker — rule targets multiple OSes generically ──
        # Also used for application-framework rules (Django, Spring, JVM, etc.)
        # and product-agnostic categories (webserver, antivirus, database).
        "cross_platform",
        UNKNOWN,
    }
)


# ---------------------------------------------------------------------------
# DATA_SOURCES — what product / integration / feed produces the telemetry
# ---------------------------------------------------------------------------

DATA_SOURCES: frozenset[str] = frozenset(
    {
        # ── Endpoint telemetry ──────────────────────────────────────────────
        "sysmon",
        "windows_security_event_log",
        "windows_powershell",
        "windows_defender_event_log",
        "auditd",
        "osquery",
        "elastic_defend",  # Elastic Endpoint Security agent
        "elastic_endgame",  # Legacy endpoint product
        "cloud_defend",      # Elastic Cloud Defend (container/K8s security agent)
        "crowdstrike_fdr",  # Falcon Data Replicator
        "defender_endpoint",  # Microsoft Defender for Endpoint (MDATP/MDE)
        "sentinelone",
        "carbon_black",
        "jamf_protect",          # macOS enterprise security via Jamf
        "cyberark_audit",        # CyberArk PAM audit logs
        "network_traffic_logs",  # Elastic Network Traffic integration (Zeek/Suricata backend)
        # ── Cloud telemetry ─────────────────────────────────────────────────
        "aws_cloudtrail",
        "aws_security_hub",
        "aws_guardduty",
        "aws_vpc_flow",
        "aws_security_lake",  # ASL (OCSF schema)
        "azure_activity",
        "azure_audit",
        "defender_cloud",  # Microsoft Defender for Cloud
        "gcp_audit",
        "gcp_vpc_flow",
        # ── Azure extras (beyond the general azure_activity) ────────────────
        "azure_risk_detection",  # Azure Risk Detection feed
        "azure_pim",             # Privileged Identity Management audit
        # ── Identity / authentication ───────────────────────────────────────
        "entra_id_signin",  # Azure AD / Entra ID sign-in logs
        "entra_id_audit",
        "m365_audit",                # M365 Unified Audit Log
        "m365_exchange_audit",       # Exchange Online mail flow / admin
        "m365_defender",             # Microsoft Defender for O365 / M365 Defender threat feeds
        "okta_system_log",
        "onelogin_events",           # OneLogin event feed
        "duo_activity",
        "google_workspace_audit",
        # ── Network telemetry ───────────────────────────────────────────────
        "zeek",
        "suricata",
        "snort",
        "palo_alto_firewall",
        "fortinet_firewall",
        "cisco_firewall",
        "cisco_aaa",
        "huawei_network",        # Huawei network devices (routers, switches)
        "juniper_network",       # Juniper network devices
        "dns_query_logs",
        "proxy_logs",
        # ── Email telemetry ─────────────────────────────────────────────────
        "email_message_metadata",  # Sublime, generic email security tools
        # ── Application / DevOps audit logs ─────────────────────────────────
        "github_audit",
        "gitlab_audit",
        "bitbucket_audit",
        "kubernetes_audit",
        # ── Generic application / infrastructure logs (product-agnostic
        # Sigma categories like `webserver`, `antivirus`, `database`) ──────
        "application_logs",   # Django / JVM / Spring / Node.js / etc.
        "webserver_logs",     # Apache / Nginx / IIS access & error logs
        "antivirus_logs",     # generic AV event feed (ClamAV, Defender, 3rd-party)
        "database_logs",      # RDBMS audit / slow query / error logs
        # ── Sigma cross-reference: generic Linux logs (when not auditd) ─────
        "linux_syslog",
        # ── LLM service logs (e.g. Bedrock, OpenAI audit) ───────────────────
        "llm_service_logs",
        # ── Generic catch-all for behavioral EDR rules with no specific feed
        "endpoint_behavior",
        # ── Sentinel-specific: SIEM-derived alerts (when source is "another
        #    SIEM's alert") ─────────────────────────────────────────────────
        "siem_alert",
        # ── Elastic Security's own alert stream (`.alerts-security-*`) —
        # used by higher-order / alert-on-alert correlation rules.
        "elastic_siem_alerts",
        # ── Elastic ML anomaly detection jobs (type="machine_learning"
        # rules that don't have an index; driven by a job config).
        "elastic_ml",
        UNKNOWN,
    }
)


# ---------------------------------------------------------------------------
# EVENT_TYPES — what kind of activity the rule looks for
# ---------------------------------------------------------------------------

EVENT_TYPES: frozenset[str] = frozenset(
    {
        # Design principle: these values mirror Sigma's `category` vocabulary
        # 1:1 wherever Sigma provides a specific category. We intentionally
        # do NOT collapse related categories (file_delete, file_block_executable,
        # file_change) into a single `file_event` bucket — detection
        # engineers filter by these specific activities and the distinctions
        # are meaningful. When a rule's logsource is a coarse channel
        # (windows/security, okta) rather than a specific category, it gets
        # the coarser `audit_event` / `api_call` classification instead of
        # being silently split into plausible sub-categories.
        #
        # Values are grouped by theme below. Count as of Issue 2 Phase 1b: 35.

        # ── Process activity (Sysmon 1, 5, 7, 8, 9, 10, 25) ────────────────
        "process_creation",          # Sysmon 1, Windows 4688
        "process_termination",       # Sysmon 5
        "image_load",                # Sysmon 7 — DLL / library load
        "driver_load",               # Sysmon 6 — kernel driver load
        "create_remote_thread",      # Sysmon 8 — thread injection
        "raw_access_thread",         # Sysmon 9 — direct disk thread manip
        "process_access",            # Sysmon 10 — LSASS read / cred dumping
        "process_tampering",         # Sysmon 25 — PPID spoofing / image swap
        # ── File activity (Sysmon 2, 11, 15, 23, 26-29) ────────────────────
        "file_event",                # Sigma generic category
        "file_change",               # Sysmon 2 — file creation time changed
        "create_stream_hash",        # Sysmon 15 — ADS creation
        "file_delete",               # Sysmon 23
        "file_delete_detected",      # Sysmon 26
        "file_block_executable",     # Sysmon 27
        "file_block_shredding",      # Sysmon 28
        "file_executable_detected",  # Sysmon 29
        "pipe_created",              # Sysmon 17, 18 — named pipe
        # ── Registry activity (Sysmon 12, 13, 14) ──────────────────────────
        "registry_event",            # Sigma generic category
        "registry_add",
        "registry_delete",
        "registry_set",              # Value modification
        "registry_rename",           # Sysmon 14
        # ── Network activity ────────────────────────────────────────────────
        "network_connection",        # Sysmon 3
        "dns_query",                 # Sysmon 22
        "http_request",
        # ── Identity / auth ─────────────────────────────────────────────────
        "authentication",
        # ── Cloud / SaaS API call (also used for Okta/M365/GitHub audit) ───
        "api_call",
        # ── Generic audit log (Windows Security/System/Application, etc.) ─
        # Coarse fallback when the logsource is a channel that contains
        # many different event types. Future work: per-vendor event-ID
        # dictionaries will refine these to more specific categories.
        "audit_event",
        # ── Sysmon / system-specific misc ──────────────────────────────────
        "wmi_event",                 # Sysmon 19, 20, 21
        "clipboard_capture",         # Sysmon 24
        "sysmon_status",             # Sysmon 4, 16 — service state changes
        "sysmon_error",              # Sysmon 255
        # ── Email message inspection (Sublime) ─────────────────────────────
        "email_message",
        # ── Hunting query — broad exploration, not a single event type ─────
        "hunting_query",
        # ── Alert correlation — rule consumes the SIEM's OWN alert stream.
        # Elastic rules querying `.alerts-security-*` are the canonical
        # case; Sentinel `SecurityAlert`-consuming rules are similar.
        # This is distinct from `platform_alert` (below) which is the
        # source alert from a security product BEFORE the SIEM correlates it.
        "alert_correlation",
        # ── Platform alert — a detection alert emitted by a security
        # product (EDR, AV, external SIEM) that is being INGESTED as a
        # rule's input. Elastic "promotion" rules are the canonical case:
        # Endgame / CrowdStrike / QRadar fire their own alerts and the
        # promotion rule wraps them into Elastic alerts. Distinct from
        # raw telemetry (process_creation etc.) because the input is
        # already an alert, and distinct from alert_correlation because
        # the alert originates OUTSIDE the SIEM.
        "platform_alert",
        # ── ML-based anomaly detection — no specific event pivot, the
        # rule fires when an ML job scores the anomaly above threshold.
        "ml_detection",
        UNKNOWN,
    }
)


# ---------------------------------------------------------------------------
# DATA_SOURCE_PLATFORMS — which platforms each data_source can produce
# telemetry for. Used to intersect-narrow data_sources against a rule's
# final platform set. Example: a rule tagged `OS: Windows` that inherits
# a `linux_syslog` data_source from its integration (because the Elastic
# `system` integration supports both Windows Event Log AND Linux syslog)
# correctly drops `linux_syslog` — a Windows rule can't consume Linux
# syslog.
#
# An EMPTY set (`frozenset()`) means the data_source is universal: it
# can apply to any platform. Used for generic categories like
# `application_logs`, `webserver_logs`, `siem_alert` that aren't bound
# to a specific OS/cloud.
#
# Data sources not in this map default to empty (universal) — safer to
# be permissive than over-prune. Filter logic in resolver.py treats
# `cross_platform` and `unknown` in the platform set as "don't narrow".
# ---------------------------------------------------------------------------

DATA_SOURCE_PLATFORMS: dict[str, frozenset[str]] = {
    # ── Windows-specific endpoint ───────────────────────────────────────
    "sysmon": frozenset({"windows"}),
    "windows_security_event_log": frozenset({"windows"}),
    "windows_powershell": frozenset({"windows"}),
    "windows_defender_event_log": frozenset({"windows"}),
    "defender_endpoint": frozenset({"windows"}),
    # ── Linux-specific endpoint ─────────────────────────────────────────
    "auditd": frozenset({"linux"}),
    "linux_syslog": frozenset({"linux"}),
    # ── macOS-specific endpoint ─────────────────────────────────────────
    "jamf_protect": frozenset({"macos"}),
    # ── Cross-OS endpoint agents (Windows + Linux + macOS) ──────────────
    "osquery": frozenset({"windows", "linux", "macos"}),
    "elastic_defend": frozenset({"windows", "linux", "macos"}),
    "elastic_endgame": frozenset({"windows", "linux", "macos"}),
    "crowdstrike_fdr": frozenset({"windows", "linux", "macos"}),
    "sentinelone": frozenset({"windows", "linux", "macos"}),
    "carbon_black": frozenset({"windows", "linux", "macos"}),
    "endpoint_behavior": frozenset({"windows", "linux", "macos"}),
    # Microsoft Defender spans both Windows endpoints and M365 services.
    "m365_defender": frozenset({"microsoft_365", "windows"}),
    # ── Container / K8s ─────────────────────────────────────────────────
    "cloud_defend": frozenset({"kubernetes"}),
    "kubernetes_audit": frozenset({"kubernetes"}),
    # ── AWS ─────────────────────────────────────────────────────────────
    "aws_cloudtrail": frozenset({"aws"}),
    "aws_security_hub": frozenset({"aws"}),
    "aws_guardduty": frozenset({"aws"}),
    "aws_vpc_flow": frozenset({"aws"}),
    "aws_security_lake": frozenset({"aws"}),
    # ── Azure ───────────────────────────────────────────────────────────
    "azure_activity": frozenset({"azure"}),
    "azure_audit": frozenset({"azure"}),
    "azure_risk_detection": frozenset({"azure"}),
    "azure_pim": frozenset({"azure"}),
    "defender_cloud": frozenset({"azure"}),
    "entra_id_signin": frozenset({"azure"}),
    "entra_id_audit": frozenset({"azure"}),
    # ── GCP ─────────────────────────────────────────────────────────────
    "gcp_audit": frozenset({"gcp"}),
    "gcp_vpc_flow": frozenset({"gcp"}),
    # ── M365 / SaaS identity ────────────────────────────────────────────
    "m365_audit": frozenset({"microsoft_365"}),
    "m365_exchange_audit": frozenset({"microsoft_365"}),
    "okta_system_log": frozenset({"okta"}),
    "onelogin_events": frozenset({"onelogin"}),
    "duo_activity": frozenset({"duo"}),
    "google_workspace_audit": frozenset({"google_workspace"}),
    # ── Network appliances ──────────────────────────────────────────────
    "zeek": frozenset({"network_appliance"}),
    "suricata": frozenset({"network_appliance"}),
    "snort": frozenset({"network_appliance"}),
    "palo_alto_firewall": frozenset({"network_appliance"}),
    "fortinet_firewall": frozenset({"network_appliance"}),
    "cisco_firewall": frozenset({"network_appliance"}),
    "cisco_aaa": frozenset({"network_appliance"}),
    "huawei_network": frozenset({"network_appliance"}),
    "juniper_network": frozenset({"network_appliance"}),
    "dns_query_logs": frozenset({"network_appliance"}),
    "proxy_logs": frozenset({"network_appliance"}),
    "network_traffic_logs": frozenset({"network_appliance"}),
    # ── Email ───────────────────────────────────────────────────────────
    "email_message_metadata": frozenset({"email"}),
    # ── DevOps / source control ─────────────────────────────────────────
    "github_audit": frozenset({"github"}),
    "gitlab_audit": frozenset({"gitlab"}),
    "bitbucket_audit": frozenset({"bitbucket"}),
    # ── LLM ─────────────────────────────────────────────────────────────
    "llm_service_logs": frozenset({"llm"}),
    # ── Universal (applies to any platform) ─────────────────────────────
    # Generic categories that can be produced on any OS/cloud:
    "application_logs": frozenset(),
    "webserver_logs": frozenset(),
    "antivirus_logs": frozenset(),
    "database_logs": frozenset(),
    # Alert streams don't belong to a single platform:
    "siem_alert": frozenset(),
    "elastic_siem_alerts": frozenset(),
    "elastic_ml": frozenset(),
    # CyberArk PAM — privileged access sits across infrastructure:
    "cyberark_audit": frozenset(),
    UNKNOWN: frozenset(),
}


def data_source_applies(data_source: str, platforms: set[str]) -> bool:
    """True if `data_source` can produce telemetry on any of `platforms`.

    Used by the resolver to prune data_sources that can't logically be
    producing events for a rule's final platform set. Conservative: if
    we have no mapping for the data_source (or platforms is empty /
    unresolved / contains `cross_platform`), return True — don't narrow.
    """
    if not platforms:
        return True
    if UNKNOWN in platforms or "cross_platform" in platforms:
        return True
    allowed = DATA_SOURCE_PLATFORMS.get(data_source)
    # Not in the map → treat as universal (safe default).
    if allowed is None or not allowed:
        return True
    return bool(allowed & platforms)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def is_canonical_platform(value: str) -> bool:
    """True if `value` is a recognized platform identifier."""
    return value in PLATFORMS


def is_canonical_data_source(value: str) -> bool:
    """True if `value` is a recognized data source identifier."""
    return value in DATA_SOURCES


def is_canonical_event_type(value: str) -> bool:
    """True if `value` is a recognized event type identifier."""
    return value in EVENT_TYPES
