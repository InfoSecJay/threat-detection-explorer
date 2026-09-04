"""Platform split (#103 / teardown R05): platforms, domains, products.

Until 2026-09 the `platforms` field mixed four axes -- operating
systems, cloud providers, SaaS applications and security products --
because Panther's log-type vocabulary was written straight into it
while Sigma, Elastic and Splunk used it for the OS. Filtering on
`crowdstrike` found Splunk and Panther rules but none of Sigma's
CrowdStrike rules (tagged `windows`), and the methodology page's
"one vocabulary" promise broke on the busiest facet.

Three public fields, each with ONE meaning:

- `platforms`  the operating system the telemetry comes from:
               windows, linux, macos, container, cross_platform,
               not_applicable (SaaS / cloud / email / network telemetry
               where an OS is meaningless), unknown.
- `domains`    where the attack surface is: endpoint, identity, cloud,
               saas, network, email, devops, data (+ unknown). A rule
               can have several. Extending the list is a table edit
               here plus a line in docs/taxonomy.md.
- `products`   the vendor / application whose telemetry the rule reads
               (aws, okta, crowdstrike, sysmon, palo_alto ...). Open
               vocabulary; empty when the telemetry is OS-native.

Everything is DERIVED at normalization from what the resolver already
produces -- the vendor mapping files keep their vocabulary (`okta`,
`crowdstrike`, `network_appliance` ... as "raw platforms") and the
canonical data sources -- so no mapping YAML changed. `split_platforms`
is a pure function; `LEGACY_PLATFORM_FILTERS` keeps old `platforms=okta`
bookmarks working by re-targeting them at the field that now holds the
value.
"""

from __future__ import annotations

from typing import Optional

from app.services.taxonomy.canonical import DATA_SOURCES, PLATFORMS, UNKNOWN

# ── Vocabulary ─────────────────────────────────────────────────────────────

OS_PLATFORMS: tuple[str, ...] = (
    "windows", "linux", "macos", "container", "cross_platform", "not_applicable", UNKNOWN,
)
_SPECIFIC_OS = ("windows", "linux", "macos")

# Order is display order (facets, chips). Crosswalk to Devo's certified
# data-source catalogue in docs/taxonomy.md; `application` (framework
# and app-server logs) is the first candidate for a ninth value.
DOMAINS: tuple[str, ...] = ("endpoint", "identity", "cloud", "saas", "network", "email", "devops", "data")

DOMAIN_DEFINITIONS: dict[str, str] = {
    "endpoint": "Host telemetry: OS event logs, Sysmon, auditd, EDR sensors, device management.",
    "identity": "Identity providers and access management: sign-ins, MFA, directory and privilege changes.",
    "cloud": "Cloud control planes and workloads: CloudTrail, Azure activity, GCP audit, Kubernetes, CNAPP findings.",
    "saas": "Application audit logs of SaaS products: M365, Google Workspace, Slack, Notion, Salesforce, LLM services.",
    "network": "Network telemetry: firewalls, proxies, DNS, IDS, flow, WAF, VPN, web-server access logs.",
    "email": "Mail flow and message security: email metadata, Sublime, Proofpoint, Exchange audit.",
    "devops": "Source control and delivery tooling: GitHub, GitLab, Bitbucket, Atlassian, Snyk.",
    "data": "Data platforms and databases: Snowflake, Databricks, MongoDB, RDBMS audit logs.",
}

# raw platform value -> (OS platform or precedence hint, domains, product)
# Hints: a specific OS wins; then container; then cross_platform (EDR
# telemetry with no OS stated applies wherever the sensor runs); then
# not_applicable; unknown when nothing at all was said.
_S = "not_applicable"
LEGACY_PLATFORM_SPLIT: dict[str, tuple[Optional[str], tuple[str, ...], Optional[str]]] = {
    "windows": ("windows", ("endpoint",), None),
    "linux": ("linux", ("endpoint",), None),
    "macos": ("macos", ("endpoint",), None),
    "cross_platform": ("cross_platform", (), None),
    UNKNOWN: (None, (), None),
    # cloud providers
    "aws": (_S, ("cloud",), "aws"),
    "azure": (_S, ("cloud",), "azure"),
    "gcp": (_S, ("cloud",), "gcp"),
    "oci": (_S, ("cloud",), "oci"),
    "kubernetes": ("container", ("cloud",), "kubernetes"),
    "docker": ("container", ("endpoint",), "docker"),
    # identity providers and access
    "okta": (_S, ("identity",), "okta"),
    "onelogin": (_S, ("identity",), "onelogin"),
    "duo": (_S, ("identity",), "duo"),
    "auth0": (_S, ("identity",), "auth0"),
    "onepassword": (_S, ("identity",), "onepassword"),
    "teleport": (_S, ("identity",), "teleport"),
    "push_security": (_S, ("identity",), "push_security"),
    # productivity suites
    "microsoft_365": (_S, ("saas",), "microsoft_365"),
    "google_workspace": (_S, ("saas",), "google_workspace"),
    # devops
    "github": (_S, ("devops",), "github"),
    "gitlab": (_S, ("devops",), "gitlab"),
    "bitbucket": (_S, ("devops",), "bitbucket"),
    "atlassian": (_S, ("devops",), "atlassian"),
    "snyk": (_S, ("devops",), "snyk"),
    # SaaS applications
    "slack": (_S, ("saas",), "slack"),
    "notion": (_S, ("saas",), "notion"),
    "asana": (_S, ("saas",), "asana"),
    "zoom": (_S, ("saas",), "zoom"),
    "box": (_S, ("saas",), "box"),
    "dropbox": (_S, ("saas",), "dropbox"),
    "docusign": (_S, ("saas",), "docusign"),
    "zendesk": (_S, ("saas",), "zendesk"),
    "tines": (_S, ("saas",), "tines"),
    "salesforce": (_S, ("saas",), "salesforce"),
    "appomni": (_S, ("saas",), "appomni"),
    "axonius": (_S, ("saas",), "axonius"),
    "socradar": (_S, ("saas",), "socradar"),
    "llm": (_S, ("saas",), None),
    # data platforms
    "databricks": (_S, ("data",), "databricks"),
    "snowflake": (_S, ("data",), "snowflake"),
    "mongodb": (_S, ("data",), "mongodb"),
    # cloud security posture
    "wiz": (_S, ("cloud",), "wiz"),
    "orca": (_S, ("cloud",), "orca"),
    "upwind": (_S, ("cloud",), "upwind"),
    "tracebit": (_S, ("cloud",), "tracebit"),
    # EDR: the sensor runs on any OS; the rule said nothing about which
    "crowdstrike": ("cross_platform", ("endpoint",), "crowdstrike"),
    "carbon_black": ("cross_platform", ("endpoint",), "carbon_black"),
    "sentinelone": ("cross_platform", ("endpoint",), "sentinelone"),
    # network SaaS and appliances
    "cloudflare": (_S, ("network",), "cloudflare"),
    "zscaler": (_S, ("network",), "zscaler"),
    "netskope": (_S, ("network",), "netskope"),
    "cisco_umbrella": (_S, ("network",), "cisco_umbrella"),
    "tailscale": (_S, ("network",), "tailscale"),
    "thinkst_canary": (_S, ("network",), "thinkst_canary"),
    "network_appliance": (_S, ("network",), None),
    # email
    "email": (_S, ("email",), None),
}

# Old `platforms=` filter values that now live in another field.
LEGACY_PLATFORM_FILTERS: dict[str, tuple[str, str]] = {
    **{v: ("products", spec[2]) for v, spec in LEGACY_PLATFORM_SPLIT.items() if spec[2]},
    "email": ("domains", "email"),
    "network_appliance": ("domains", "network"),
    "llm": ("domains", "saas"),
}


def _prefixed(*prefixes: str) -> frozenset[str]:
    return frozenset(d for d in DATA_SOURCES if any(d == p.rstrip("_") or d.startswith(p) for p in prefixes))


# data source -> domains it belongs to (a source can sit in two: Exchange
# audit is SaaS and email; a VPC flow log is cloud and network).
_DOMAIN_SOURCES: dict[str, frozenset[str]] = {
    "endpoint": frozenset({
        "sysmon", "windows_security_event_log", "windows_powershell", "windows_defender_event_log",
        "windows_event_logs", "auditd", "osquery", "linux_syslog", "elastic_defend", "elastic_endgame",
        "cloud_defend", "crowdstrike_fdr", "defender_endpoint", "sentinelone", "carbon_black", "jamf_protect",
        "endpoint_behavior", "antivirus_logs", "cyberark_epm",
    }) | _prefixed("crowdstrike_event_streams", "crowdstrike_detection_summary", "microsoft_intune_"),
    "identity": frozenset({
        "entra_id_signin", "entra_id_audit", "azure_pim", "azure_risk_detection", "okta_system_log",
        "okta_scheduled_query", "onelogin_events", "duo_activity", "duo_administrator", "duo_authentication",
        "auth0_logs", "teleport_audit", "push_security_audit", "sailpoint_idn_audit", "cyberark_audit",
        "crowdstrike_identity_protection",
    }) | _prefixed("onepassword_"),
    "cloud": frozenset({
        "azure_activity", "azure_audit", "defender_cloud", "kubernetes_audit", "oci_audit", "prisma_cloud_audit",
        "orca_alert", "upwind_detection", "azure_firewall", "azure_app_service", "tracebit_alert", "cloud_defend",
    }) | _prefixed("aws_", "gcp_", "wiz_"),
    "saas": frozenset({
        "m365_audit", "m365_sharepoint_audit", "m365_exchange_audit", "m365_defender", "m365_purview_audit",
        "google_workspace_audit", "slack_audit", "notion_audit", "asana_audit", "box_event", "dropbox_team_event",
        "docusign_connect", "zendesk_audit", "tines_audit", "appomni_alerts", "axonius_activity",
        "socradar_incidents", "openai_audit", "anthropic_activity", "llm_service_logs", "aws_bedrock_invocation",
        "trend_micro_cas", "panther_audit", "splunk_internal_logs", "sublime_audit",
        "microsoft_graph_security_alerts",
    }) | _prefixed("zoom_", "salesforce_"),
    "network": frozenset({
        "zeek", "suricata", "snort", "palo_alto_firewall", "fortinet_firewall", "cisco_firewall", "cisco_aaa",
        "huawei_network", "juniper_network", "dns_query_logs", "proxy_logs", "network_traffic_logs",
        "ocsf_network_activity", "ocsf_dns_activity", "zscaler_zia_admin_audit", "netskope_audit",
        "cisco_umbrella_dns", "tailscale_audit", "thinkst_canary_alert", "imperva_waf", "vpn_logs",
        "webserver_logs", "azure_firewall", "aws_vpc_flow", "aws_vpc_dns", "aws_waf_web_acl", "aws_alb_access",
        "gcp_vpc_flow", "gcp_dns", "gcp_http_load_balancer", "crowdstrike_dns_request",
    }) | _prefixed("cloudflare_"),
    "email": frozenset({
        "email_message_metadata", "proofpoint_event", "sublime_message_event", "m365_exchange_audit", "m365_defender",
    }),
    "devops": frozenset({"bitbucket_audit", "atlassian_audit", "gitlab_production"})
    | _prefixed("github_", "gitlab_audit", "snyk_"),
    "data": frozenset({"databricks_audit", "database_logs"}) | _prefixed("snowflake_", "mongodb_"),
}

# Sources that carry no domain on their own: alert streams and generic
# application logs. They keep whatever the raw platform said.
NO_DOMAIN_SOURCES: frozenset[str] = frozenset({
    "application_logs", "siem_alert", "elastic_siem_alerts", "elastic_ml", "third_party_security_alerts", UNKNOWN,
})

DATA_SOURCE_DOMAINS: dict[str, tuple[str, ...]] = {}
for _domain in DOMAINS:
    for _ds in _DOMAIN_SOURCES[_domain]:
        DATA_SOURCE_DOMAINS[_ds] = (*DATA_SOURCE_DOMAINS.get(_ds, ()), _domain)

# data source -> vendor / application product. OS-native telemetry and
# generic categories map to None on purpose.
_PRODUCT_PREFIXES: tuple[tuple[str, str], ...] = (
    ("aws_", "aws"), ("azure_", "azure"), ("entra_id_", "azure"), ("gcp_", "gcp"), ("m365_", "microsoft_365"),
    ("microsoft_intune_", "microsoft_intune"), ("okta_", "okta"), ("duo_", "duo"), ("onepassword_", "onepassword"),
    ("github_", "github"), ("gitlab_", "gitlab"), ("snyk_", "snyk"), ("slack_", "slack"), ("notion_", "notion"),
    ("asana_", "asana"), ("zoom_", "zoom"), ("salesforce_", "salesforce"), ("snowflake_", "snowflake"),
    ("mongodb_", "mongodb"), ("wiz_", "wiz"), ("crowdstrike_", "crowdstrike"), ("cloudflare_", "cloudflare"),
    ("sublime_", "sublime"), ("cyberark_", "cyberark"), ("elastic_siem_alerts", "elastic_security"),
    ("elastic_ml", "elastic_security"),
)
_PRODUCT_EXACT: dict[str, Optional[str]] = {
    "sysmon": "sysmon", "auditd": "auditd", "osquery": "osquery", "elastic_defend": "elastic_defend",
    "elastic_endgame": "elastic_endgame", "cloud_defend": "elastic_cloud_defend", "defender_endpoint": "microsoft_defender",
    "windows_defender_event_log": "microsoft_defender", "defender_cloud": "microsoft_defender", "m365_defender": "microsoft_defender",
    "sentinelone": "sentinelone", "carbon_black": "carbon_black", "jamf_protect": "jamf",
    "kubernetes_audit": "kubernetes", "aws_eks_audit": "kubernetes", "oci_audit": "oci", "prisma_cloud_audit": "prisma_cloud",
    "orca_alert": "orca", "upwind_detection": "upwind", "tracebit_alert": "tracebit", "appomni_alerts": "appomni",
    "axonius_activity": "axonius", "socradar_incidents": "socradar", "trend_micro_cas": "trend_micro",
    "onelogin_events": "onelogin", "auth0_logs": "auth0", "google_workspace_audit": "google_workspace",
    "teleport_audit": "teleport", "push_security_audit": "push_security", "sailpoint_idn_audit": "sailpoint",
    "zeek": "zeek", "suricata": "suricata", "snort": "snort", "palo_alto_firewall": "palo_alto",
    "fortinet_firewall": "fortinet", "cisco_firewall": "cisco", "cisco_aaa": "cisco", "huawei_network": "huawei",
    "juniper_network": "juniper", "zscaler_zia_admin_audit": "zscaler", "netskope_audit": "netskope",
    "cisco_umbrella_dns": "cisco_umbrella", "tailscale_audit": "tailscale", "thinkst_canary_alert": "thinkst_canary",
    "imperva_waf": "imperva", "proofpoint_event": "proofpoint", "bitbucket_audit": "bitbucket",
    "atlassian_audit": "atlassian", "box_event": "box", "dropbox_team_event": "dropbox", "docusign_connect": "docusign",
    "zendesk_audit": "zendesk", "tines_audit": "tines", "databricks_audit": "databricks", "openai_audit": "openai",
    "anthropic_activity": "anthropic", "panther_audit": "panther", "splunk_internal_logs": "splunk",
    "microsoft_graph_security_alerts": "microsoft_graph",
    # OS-native or generic: no product
    "windows_security_event_log": None, "windows_powershell": None, "windows_event_logs": None, "linux_syslog": None,
    "endpoint_behavior": None, "antivirus_logs": None, "application_logs": None, "webserver_logs": None,
    "database_logs": None, "dns_query_logs": None, "proxy_logs": None, "network_traffic_logs": None, "vpn_logs": None,
    "email_message_metadata": None, "llm_service_logs": None, "siem_alert": None, "third_party_security_alerts": None,
    "ocsf_network_activity": None, "ocsf_dns_activity": None, "crowdstrike_fdr": "crowdstrike", UNKNOWN: None,
}


def product_for_data_source(data_source: str) -> Optional[str]:
    if data_source in _PRODUCT_EXACT:
        return _PRODUCT_EXACT[data_source]
    for prefix, product in _PRODUCT_PREFIXES:
        if data_source.startswith(prefix):
            return product
    return None


DATA_SOURCE_PRODUCTS: dict[str, Optional[str]] = {ds: product_for_data_source(ds) for ds in DATA_SOURCES}


def _dedupe(values, order: Optional[tuple[str, ...]] = None) -> list[str]:
    seen = list(dict.fromkeys(v for v in values if v))
    if order is None:
        return seen
    rank = {v: i for i, v in enumerate(order)}
    return sorted(seen, key=lambda v: (rank.get(v, len(rank)), v))


def split_platforms(raw_platforms, data_sources) -> tuple[list[str], list[str], list[str]]:
    """(platforms, domains, products) from the resolver's raw platforms
    and canonical data sources. Never returns an empty platforms or
    domains list (`unknown` fills them); products may be empty."""
    raw = [p for p in (raw_platforms or []) if isinstance(p, str)]
    sources = [d for d in (data_sources or []) if isinstance(d, str)]

    os_values: list[str] = []
    hints: list[str] = []
    passthrough: list[str] = []
    domains: list[str] = []
    products: list[str] = []
    for p in raw:
        spec = LEGACY_PLATFORM_SPLIT.get(p)
        if spec is None:
            # Already-split value (a re-normalization of stored rows), or
            # a value nobody classified: kept as-is rather than silently
            # dropped, so it shows up in the facet and gets a rule added
            # (test_taxonomy_domains guards the canonical vocabulary).
            if p in _SPECIFIC_OS:
                os_values.append(p)
            elif p in OS_PLATFORMS and p != UNKNOWN:
                hints.append(p)
            elif p != UNKNOWN:
                passthrough.append(p)
            continue
        os_hint, doms, product = spec
        if os_hint in _SPECIFIC_OS:
            os_values.append(os_hint)
        elif os_hint:
            hints.append(os_hint)
        domains.extend(doms)
        if product:
            products.append(product)

    for ds in sources:
        domains.extend(DATA_SOURCE_DOMAINS.get(ds, ()))
        product = DATA_SOURCE_PRODUCTS.get(ds)
        if product:
            products.append(product)

    if os_values:
        platforms = _dedupe(os_values, _SPECIFIC_OS)
    elif "container" in hints:
        platforms = ["container"]
    elif "cross_platform" in hints:
        platforms = ["cross_platform"]
    elif "not_applicable" in hints:
        platforms = ["not_applicable"]
    elif passthrough:
        platforms = _dedupe(passthrough)
    else:
        platforms = [UNKNOWN]

    return platforms, _dedupe(domains, DOMAINS) or [UNKNOWN], _dedupe(products)


def is_canonical_domain(value: str) -> bool:
    return value in DOMAINS or value == UNKNOWN


__all__ = [
    "OS_PLATFORMS", "DOMAINS", "DOMAIN_DEFINITIONS", "LEGACY_PLATFORM_SPLIT", "LEGACY_PLATFORM_FILTERS",
    "DATA_SOURCE_DOMAINS", "DATA_SOURCE_PRODUCTS", "NO_DOMAIN_SOURCES", "PLATFORMS",
    "split_platforms", "product_for_data_source", "is_canonical_domain",
]
