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
        "aws",
        "azure",
        "gcp",
        # ── Identity / SaaS productivity platforms ──────────────────────────
        "azure_ad",  # also covers Entra ID (modern Azure AD)
        "okta",
        "google_workspace",
        "microsoft_365",
        "duo",
        # ── DevOps / source control ─────────────────────────────────────────
        "github",
        "gitlab",
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
        "cross_platform",
        # ── Sentinel: unknown
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
        "crowdstrike_fdr",  # Falcon Data Replicator
        "defender_endpoint",  # Microsoft Defender for Endpoint (MDATP/MDE)
        "sentinelone",
        "carbon_black",
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
        # ── Identity / authentication ───────────────────────────────────────
        "entra_id_signin",  # Azure AD / Entra ID sign-in logs
        "entra_id_audit",
        "m365_audit",
        "m365_exchange_audit",
        "okta_system_log",
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
        "dns_query_logs",
        "proxy_logs",
        # ── Email telemetry ─────────────────────────────────────────────────
        "email_message_metadata",  # Sublime, generic email security tools
        # ── Application / DevOps audit logs ─────────────────────────────────
        "github_audit",
        "gitlab_audit",
        "kubernetes_audit",
        # ── Sigma cross-reference: generic Linux logs (when not auditd) ─────
        "linux_syslog",
        # ── LLM service logs (e.g. Bedrock, OpenAI audit) ───────────────────
        "llm_service_logs",
        # ── Generic catch-all for behavioral EDR rules with no specific feed
        "endpoint_behavior",
        # ── Sentinel-specific: SIEM-derived alerts (when source is "another
        #    SIEM's alert") ─────────────────────────────────────────────────
        "siem_alert",
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
        UNKNOWN,
    }
)


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
