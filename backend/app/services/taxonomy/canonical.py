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
        "auth0",
        # ── DevOps / source control ─────────────────────────────────────────
        "github",
        "gitlab",
        "bitbucket",
        "atlassian",         # Jira / Confluence audit (Atlassian Access)
        "snyk",              # Snyk security audit
        # ── SaaS productivity + collaboration (Panther onboarding) ──────────
        "slack",
        "notion",
        "asana",
        "zoom",
        "box",
        "dropbox",
        "docusign",
        "zendesk",
        "tines",             # SOAR / workflow audit
        # ── Identity + password managers (Panther onboarding) ───────────────
        "onepassword",
        # ── Data platforms + cloud security posture (Panther onboarding) ────
        "databricks",
        "snowflake",
        "mongodb",
        "wiz",               # CNAPP / cloud security posture
        "orca",              # Orca Security CNAPP
        # ── EDR / security tools (Panther onboarding) ───────────────────────
        "crowdstrike",
        "carbon_black",
        "sentinelone",
        # ── Network security SaaS (Panther onboarding) ──────────────────────
        "cloudflare",
        "zscaler",
        "netskope",
        "cisco_umbrella",
        "tailscale",
        # ── Access + zero-trust (Panther onboarding) ────────────────────────
        "teleport",          # Gravitational Teleport audit
        "push_security",
        # ── Deception + alerting SaaS (Panther onboarding) ──────────────────
        "thinkst_canary",
        "tracebit",
        "socradar",
        "upwind",
        "axonius",
        "appomni",
        "salesforce",
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
        "auth0_logs",                # Auth0 tenant logs (authentication + management API)
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
        # ── AWS additions (Panther onboarding) ──────────────────────────────
        "aws_alb_access",              # Application Load Balancer access logs
        "aws_s3_server_access",        # S3 bucket access logs
        "aws_waf_web_acl",             # AWS WAF web ACL logs
        "aws_vpc_dns",                 # AWS VPC Route53 resolver query logs
        "aws_bedrock_invocation",      # AWS Bedrock model invocation
        "aws_eks_audit",               # EKS control-plane audit (K8s audit on AWS)
        # ── Azure / M365 additions (Panther onboarding) ─────────────────────
        "azure_monitor_activity",      # Azure Monitor activity logs (subscription-scoped)
        "microsoft_intune_audit",
        "microsoft_intune_operational",
        "microsoft_defender_xdr",      # M365 Defender XDR advanced hunting
        "microsoft_graph_security_alerts",
        "microsoft365_sharepoint_audit",
        "microsoft365_exchange_audit",
        # ── GCP additions (Panther onboarding) ──────────────────────────────
        "gcp_http_load_balancer",
        # ── DevOps additions (Panther onboarding) ───────────────────────────
        "github_webhook",
        "gitlab_production",           # GitLab production/application logs
        "atlassian_audit",
        "snyk_org_audit",
        "snyk_group_audit",
        # ── SaaS audit feeds (Panther onboarding) ───────────────────────────
        "slack_audit",
        "notion_audit",
        "asana_audit",
        "zoom_operation",
        "zoom_activity",
        "box_event",
        "dropbox_team_event",
        "docusign_connect",
        "zendesk_audit",
        "tines_audit",
        "salesforce_realtime",
        "salesforce_login_as",
        # ── Identity / password (Panther onboarding) ────────────────────────
        "onepassword_signin",
        "onepassword_item_usage",
        "duo_administrator",           # Panther distinguishes administrator vs authentication
        "duo_authentication",
        # ── Data platforms (Panther onboarding) ─────────────────────────────
        "databricks_audit",
        "snowflake_query_history",
        "snowflake_login_history",
        "snowflake_grants",
        "snowflake_data_transfer",
        "mongodb_org_audit",
        "mongodb_project_audit",
        # ── Cloud security posture (Panther onboarding) ─────────────────────
        "wiz_audit",
        "wiz_detection",
        "wiz_issue",
        "orca_alert",
        "upwind_detection",
        "appomni_alerts",
        "axonius_activity",
        # ── EDR extras (Panther onboarding) ─────────────────────────────────
        "crowdstrike_event_streams",
        "crowdstrike_dns_request",
        "crowdstrike_detection_summary",
        "carbon_black_audit",
        "carbon_black_alert",
        "sentinelone_activity",
        # ── Network SaaS (Panther onboarding) ───────────────────────────────
        "cloudflare_firewall",
        "cloudflare_http",
        "zscaler_zia_admin_audit",
        "netskope_audit",
        "cisco_umbrella_dns",
        "tailscale_audit",
        # ── Access / zero-trust (Panther onboarding) ────────────────────────
        "teleport_audit",
        "push_security_audit",
        # ── Deception + threat intel (Panther onboarding) ───────────────────
        "thinkst_canary_alert",
        "tracebit_alert",
        "socradar_incidents",
        # ── LLM extras (Panther onboarding) ─────────────────────────────────
        "openai_audit",
        "anthropic_activity",
        # ── Panther meta ────────────────────────────────────────────────────
        "panther_audit",               # Panther's own audit log (self-hosted platform)
        "okta_scheduled_query",        # Panther runs scheduled Okta queries and emits results
        # ── Sublime extras — Panther has Sublime.Audit + MessageEvent ───────
        "sublime_audit",
        "sublime_message_event",
        # ── Proofpoint (Panther has Proofpoint.Event) ───────────────────────
        "proofpoint_event",
        # ── OCSF (Open Cybersecurity Schema Framework) ──────────────────────
        "ocsf_network_activity",
        "ocsf_dns_activity",
        # ── Windows event logs (Panther explicit LogType) ───────────────────
        "windows_event_logs",
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
    "aws_alb_access": frozenset({"aws"}),
    "aws_s3_server_access": frozenset({"aws"}),
    "aws_waf_web_acl": frozenset({"aws"}),
    "aws_vpc_dns": frozenset({"aws"}),
    "aws_bedrock_invocation": frozenset({"aws", "llm"}),
    "aws_eks_audit": frozenset({"aws", "kubernetes"}),
    # ── Azure ───────────────────────────────────────────────────────────
    "azure_activity": frozenset({"azure"}),
    "azure_audit": frozenset({"azure"}),
    "azure_monitor_activity": frozenset({"azure"}),
    "azure_risk_detection": frozenset({"azure"}),
    "azure_pim": frozenset({"azure"}),
    "defender_cloud": frozenset({"azure"}),
    "entra_id_signin": frozenset({"azure"}),
    "entra_id_audit": frozenset({"azure"}),
    "microsoft_intune_audit": frozenset({"microsoft_365"}),
    "microsoft_intune_operational": frozenset({"microsoft_365"}),
    "microsoft_defender_xdr": frozenset({"microsoft_365", "windows"}),
    "microsoft_graph_security_alerts": frozenset({"microsoft_365"}),
    "microsoft365_sharepoint_audit": frozenset({"microsoft_365"}),
    "microsoft365_exchange_audit": frozenset({"microsoft_365"}),
    # ── GCP ─────────────────────────────────────────────────────────────
    "gcp_audit": frozenset({"gcp"}),
    "gcp_vpc_flow": frozenset({"gcp"}),
    "gcp_http_load_balancer": frozenset({"gcp"}),
    # ── M365 / SaaS identity ────────────────────────────────────────────
    "m365_audit": frozenset({"microsoft_365"}),
    "m365_exchange_audit": frozenset({"microsoft_365"}),
    "okta_system_log": frozenset({"okta"}),
    "onelogin_events": frozenset({"onelogin"}),
    "duo_activity": frozenset({"duo"}),
    "auth0_logs": frozenset({"auth0"}),
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
    "github_webhook": frozenset({"github"}),
    "gitlab_audit": frozenset({"gitlab"}),
    "gitlab_production": frozenset({"gitlab"}),
    "bitbucket_audit": frozenset({"bitbucket"}),
    "atlassian_audit": frozenset({"atlassian"}),
    "snyk_org_audit": frozenset({"snyk"}),
    "snyk_group_audit": frozenset({"snyk"}),
    # ── LLM ─────────────────────────────────────────────────────────────
    "llm_service_logs": frozenset({"llm"}),
    "openai_audit": frozenset({"llm"}),
    "anthropic_activity": frozenset({"llm"}),
    # ── SaaS audit feeds (each vendor is its own platform) ──────────────
    "slack_audit": frozenset({"slack"}),
    "notion_audit": frozenset({"notion"}),
    "asana_audit": frozenset({"asana"}),
    "zoom_operation": frozenset({"zoom"}),
    "zoom_activity": frozenset({"zoom"}),
    "box_event": frozenset({"box"}),
    "dropbox_team_event": frozenset({"dropbox"}),
    "docusign_connect": frozenset({"docusign"}),
    "zendesk_audit": frozenset({"zendesk"}),
    "tines_audit": frozenset({"tines"}),
    "salesforce_realtime": frozenset({"salesforce"}),
    "salesforce_login_as": frozenset({"salesforce"}),
    "onepassword_signin": frozenset({"onepassword"}),
    "onepassword_item_usage": frozenset({"onepassword"}),
    "duo_administrator": frozenset({"duo"}),
    "duo_authentication": frozenset({"duo"}),
    # ── Data platforms ──────────────────────────────────────────────────
    "databricks_audit": frozenset({"databricks"}),
    "snowflake_query_history": frozenset({"snowflake"}),
    "snowflake_login_history": frozenset({"snowflake"}),
    "snowflake_grants": frozenset({"snowflake"}),
    "snowflake_data_transfer": frozenset({"snowflake"}),
    "mongodb_org_audit": frozenset({"mongodb"}),
    "mongodb_project_audit": frozenset({"mongodb"}),
    # ── Cloud security posture (CNAPP) ──────────────────────────────────
    "wiz_audit": frozenset({"wiz"}),
    "wiz_detection": frozenset({"wiz"}),
    "wiz_issue": frozenset({"wiz"}),
    "orca_alert": frozenset({"orca"}),
    "upwind_detection": frozenset({"upwind"}),
    "appomni_alerts": frozenset({"appomni"}),
    "axonius_activity": frozenset({"axonius"}),
    # ── EDR extras ──────────────────────────────────────────────────────
    "crowdstrike_event_streams": frozenset({"crowdstrike"}),
    "crowdstrike_dns_request": frozenset({"crowdstrike"}),
    "crowdstrike_detection_summary": frozenset({"crowdstrike"}),
    "carbon_black_audit": frozenset({"carbon_black"}),
    "carbon_black_alert": frozenset({"carbon_black"}),
    "sentinelone_activity": frozenset({"sentinelone"}),
    # ── Network SaaS ────────────────────────────────────────────────────
    "cloudflare_firewall": frozenset({"cloudflare"}),
    "cloudflare_http": frozenset({"cloudflare"}),
    "zscaler_zia_admin_audit": frozenset({"zscaler"}),
    "netskope_audit": frozenset({"netskope"}),
    "cisco_umbrella_dns": frozenset({"cisco_umbrella"}),
    "tailscale_audit": frozenset({"tailscale"}),
    # ── Access / zero-trust ─────────────────────────────────────────────
    "teleport_audit": frozenset({"teleport"}),
    "push_security_audit": frozenset({"push_security"}),
    # ── Deception + threat intel SaaS ───────────────────────────────────
    "thinkst_canary_alert": frozenset({"thinkst_canary"}),
    "tracebit_alert": frozenset({"tracebit"}),
    "socradar_incidents": frozenset({"socradar"}),
    # ── Sublime extras (Panther) ────────────────────────────────────────
    "sublime_audit": frozenset({"email"}),
    "sublime_message_event": frozenset({"email"}),
    "proofpoint_event": frozenset({"email"}),
    # ── OCSF (schema-neutral; used with AWS Security Lake, others) ──────
    "ocsf_network_activity": frozenset(),
    "ocsf_dns_activity": frozenset(),
    # ── Panther meta ────────────────────────────────────────────────────
    "panther_audit": frozenset(),
    "okta_scheduled_query": frozenset({"okta"}),
    # ── Windows event logs (Panther has this explicit type) ─────────────
    "windows_event_logs": frozenset({"windows"}),
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


# ---------------------------------------------------------------------------
# OBSERVABLE SCHEMA — extracted_observables `type` / `subtype` vocabulary
# ---------------------------------------------------------------------------
# Single source of truth for the `type` and `subtype` values an
# ExtractedObservable may carry (issue #6, phase 1). The extractor's
# FIELD_TYPE_MAP and its heuristic fallback must only emit pairs listed
# here — a test pins that, so adding a new pair means adding it HERE
# first, deliberately.
#
# Two tiers of subtype:
#
# - Precise subtypes ("process_name", "api_action", "sender_domain")
#   come from FIELD_TYPE_MAP entries — a known field name mapped by
#   hand.
# - `*_field` subtypes ("process_field", "network_field", ...) are the
#   heuristic fallback's admission that it only recognized the DOMAIN
#   of an unmapped field, not its meaning. They are transitional: the
#   per-source extractor rebuilds (issue #6) should shrink their share
#   in favor of precise subtypes, and the extraction audit
#   (scripts/audit_extraction.py) reports that share per source.
#
# ("other", "unknown") is the fallback of last resort — the field name
# matched no domain heuristic at all.

OBSERVABLE_TYPES: frozenset[str] = frozenset(
    {
        "process",         # process execution: names, paths, command lines, hashes
        "file",            # filesystem artifacts: names, paths, extensions, hashes
        "registry",        # Windows registry keys and values
        "network",         # connections: IPs, ports, domains, URLs, protocols
        "dns",             # DNS-specific: query names/types, answers, rcodes
        "email",           # email channel: senders, recipients, subjects, attachments
        "cloud",           # cloud control plane: API actions, principals, resources
        "identity",        # identity providers: actors, targets, auth factors
        "authentication",  # OS/host logon telemetry: users, logon types/ids
        "endpoint",        # host identity: hostnames, device ids
        "event",           # bare event identifiers (Windows Event ID etc.)
        "other",           # unclassifiable field — extraction gap signal
    }
)

OBSERVABLE_SUBTYPES: dict[str, frozenset[str]] = {
    "process": frozenset(
        {
            "process_name",
            "process_path",
            "process_hash",
            "command_line_pattern",
            "parent_process_name",
            "parent_process_path",
            "parent_command_line",
            "code_signature",   # signer name/status/trust
            "call_stack",       # EDR call-stack summaries and modules
            "api_call",         # endpoint API telemetry (VirtualProtect...)
            "service_name",     # Windows service name
            "integrity_level",  # token integrity level
            "process_field",  # heuristic fallback
        }
    ),
    "file": frozenset(
        {
            "file_name",
            "file_path",
            "file_extension",
            "file_hash",
            "file_content",
            "code_signature",
            "file_field",  # heuristic fallback
        }
    ),
    "registry": frozenset(
        {
            "registry_key",
            "registry_value",
            "registry_field",  # heuristic fallback
        }
    ),
    "network": frozenset(
        {
            "ip_address",
            "port",
            "domain",
            "url",
            "protocol",
            "direction",
            "action",
            "http_method",
            "http_status",
            # Legacy pin: FIELD_TYPE_MAP maps `network.type`-style
            # fields to the literal subtype "type". Rename to
            # `network_type` during the network extractor rebuild.
            "type",
            "user_agent",
            "network_field",  # heuristic fallback
        }
    ),
    "dns": frozenset(
        {
            "query_name",
            "query_type",
            "answer",
            "answer_type",
            "response_code",
            "dns_field",  # heuristic fallback
        }
    ),
    "email": frozenset(
        {
            "sender",
            "sender_name",
            "sender_domain",
            "recipient",
            "reply_to",
            "return_path",
            "subject",
            "body_content",
            "attachment",
            "attachment_type",
            "url",
            "auth_result",
            "ml_classifier",
            "attachment_content",  # OCR/strings/exif scans of attachments
            "header",              # raw header fields (hops, message-id)
            "email_field",  # heuristic fallback
        }
    ),
    "cloud": frozenset(
        {
            "api_action",
            "event_source",
            "principal",
            "principal_type",
            "account_id",
            "resource",
            "resource_type",
            "resource_group",
            "region",
            "cloud_provider",
            "source_ip",
            "user_agent",
            "request_params",
            "response_elements",
            "error_code",
            "error_message",
            "result",
            "context",
        }
    ),
    "identity": frozenset(
        {
            "action",
            "actor",
            "target",
            "target_type",
            "auth_factor",
            "outcome",
            "outcome_reason",
            "risk",
            "device",
            "geo",
            "source_ip",
            "user_agent",
            "context",
            "identity_field",  # heuristic fallback
        }
    ),
    "authentication": frozenset(
        {
            "user",
            "user_id",
            "user_email",
            "domain",
            "logon_id",
            "logon_type",
            "auth_field",  # heuristic fallback
        }
    ),
    "endpoint": frozenset(
        {
            "hostname",
            "remote_hostname",
            "device_id",
            "os",  # host.os.type/family — OS routing metadata
        }
    ),
    "event": frozenset(
        {
            "event_id",
            # Telemetry-stream metadata (issue #6 vocabulary pass):
            # not domain observables, but knowing WHAT the rule keys on
            # beats other/unknown.
            "event_category",  # event.type/category/kind
            "event_source",    # event.dataset/module, CEF vendor/product
            "event_outcome",   # event.outcome, status fields
            "severity",        # severity/priority columns
            # ECS event.action on endpoint / generic streams: the
            # telemetry verb ("start", "exec", "creation"). The Elastic
            # extractor promotes it to cloud/api_action or
            # identity/action only when the rule's context (index
            # pattern, dataset, EQL category...) says the stream is a
            # cloud or identity audit log -- see
            # field_extractor.resolve_event_action_domain.
            "event_action",
        }
    ),
    "other": frozenset({UNKNOWN}),
}


def is_valid_observable_type(obs_type: str) -> bool:
    """True if `obs_type` is a recognized observable type."""
    return obs_type in OBSERVABLE_TYPES


def is_valid_observable(obs_type: str, obs_subtype: str) -> bool:
    """True if the (type, subtype) pair is in the pinned vocabulary."""
    return obs_subtype in OBSERVABLE_SUBTYPES.get(obs_type, frozenset())


def is_canonical_data_source(value: str) -> bool:
    """True if `value` is a recognized data source identifier."""
    return value in DATA_SOURCES


def is_canonical_event_type(value: str) -> bool:
    """True if `value` is a recognized event type identifier."""
    return value in EVENT_TYPES
