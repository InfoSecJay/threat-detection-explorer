/**
 * Display labels and one-line definitions for the CLOSED taxonomy
 * vocabularies (#103 / #134). Raw ids stay the filter keys and the API
 * values; these only prettify. Mirrors DOMAIN_DEFINITIONS in
 * backend/app/services/taxonomy/domains.py -- keep the two in step.
 */

export const PLATFORM_LABELS: Record<string, string> = {
  windows: 'Windows',
  linux: 'Linux',
  macos: 'macOS',
  container: 'containers',
  cross_platform: 'any OS',
  not_applicable: 'no OS',
  unknown: 'unknown',
};

export const PLATFORM_DEFINITIONS: Record<string, string> = {
  windows: 'Telemetry from Windows hosts.',
  linux: 'Telemetry from Linux hosts.',
  macos: 'Telemetry from macOS hosts.',
  container: 'Container runtime or Kubernetes control-plane telemetry.',
  cross_platform: 'Applies wherever the sensor or agent runs; the rule does not pin an OS.',
  not_applicable: 'SaaS, cloud, identity, email or network telemetry: an operating system is meaningless here.',
  unknown: 'The rule does not say and nothing could be derived.',
};

export const DOMAIN_LABELS: Record<string, string> = {
  endpoint: 'hosts, EDR',
  identity: 'IdP, MFA, directory',
  cloud: 'control planes, K8s',
  saas: 'app audit logs',
  network: 'firewall, proxy, DNS',
  email: 'mail flow',
  devops: 'source control, CI',
  data: 'warehouses, databases',
  unknown: 'unplaced',
};

export const DOMAIN_DEFINITIONS: Record<string, string> = {
  endpoint: 'Host telemetry: OS event logs, Sysmon, auditd, EDR sensors, device management.',
  identity: 'Identity providers and access management: sign-ins, MFA, directory and privilege changes.',
  cloud: 'Cloud control planes and workloads: CloudTrail, Azure activity, GCP audit, Kubernetes, CNAPP findings.',
  saas: 'Application audit logs of SaaS products: M365, Google Workspace, Slack, Notion, Salesforce, LLM services.',
  network: 'Network telemetry: firewalls, proxies, DNS, IDS, flow, WAF, VPN, web-server access logs.',
  email: 'Mail flow and message security: email metadata, Sublime, Proofpoint, Exchange audit.',
  devops: 'Source control and delivery tooling: GitHub, GitLab, Bitbucket, Atlassian, Snyk.',
  data: 'Data platforms and databases: Snowflake, Databricks, MongoDB, RDBMS audit logs.',
  unknown: 'No domain could be derived: framework or application logs, alert streams.',
};

/** The eight closed domain values in display order. */
export const DOMAIN_VALUES = ['endpoint', 'identity', 'cloud', 'saas', 'network', 'email', 'devops', 'data'] as const;

/** OS values worth showing next to a domain; the rest add nothing. */
export const OS_PLATFORMS = new Set(['windows', 'linux', 'macos', 'container']);

/** What a row should say about where a rule applies (#134): its
 * domains, then the OS when it is a real one. Falls back to the raw
 * platforms while `domains` is still empty (rows from before the
 * split, until the nightly re-normalization fills them). */
export function whereItApplies(d: { domains?: string[]; platforms?: string[] }): string[] {
  const domains = d.domains ?? [];
  if (domains.length === 0) return d.platforms ?? [];
  const os = (d.platforms ?? []).filter((p) => OS_PLATFORMS.has(p));
  return [...domains, ...os];
}

export function taxonomyHint(kind: 'platforms' | 'domains', value: string): string | undefined {
  return kind === 'domains' ? DOMAIN_DEFINITIONS[value] : PLATFORM_DEFINITIONS[value];
}
