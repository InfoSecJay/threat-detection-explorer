"""Observable pages: everything the corpus knows about one extracted
value (a process name, event ID, file path, registry key, network
indicator, API action, source table, or target resource).

Each surface maps to one `extracted_*` JSON-list column. Matching is
whole-element, case-insensitive (`%"value"%` on the JSON text -- the
same semantics as the query bar's `process:` / `eventid:` fields), so
`mimikatz.exe` does not match `notmimikatz.exe`.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Optional

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.taxonomy.auth0_events import lookup as lookup_auth0_event
from app.services.taxonomy.event_ids import lookup as lookup_event_id

# URL segment -> (column, SearchFilters key for the catalog link, label)
OBSERVABLE_TYPES: dict[str, tuple[str, str, str]] = {
    "process": ("extracted_process_names", "process_names", "Process"),
    "path": ("extracted_file_paths", "file_paths", "File path"),
    "registry": ("extracted_registry_keys", "registry_keys", "Registry key"),
    "network": ("extracted_network_indicators", "network_indicators", "Network indicator"),
    "action": ("extracted_api_actions", "api_actions", "API action"),
    "eventid": ("extracted_event_ids", "event_ids", "Event ID"),
    "table": ("extracted_source_tables", "source_tables", "Source table"),
    "resource": ("extracted_target_resources", "target_resources", "Resource type"),
}

_CO_OCCUR_SURFACES = ("process", "eventid", "action", "table", "path", "registry", "network")

# Human names for the audit logs API actions come from. Anything else
# falls back to the canonical data-source name, prettified.
DATA_SOURCE_LABELS: dict[str, str] = {
    "aws_cloudtrail": "AWS CloudTrail",
    "aws_security_lake": "AWS Security Lake",
    "aws_eks_audit": "AWS EKS audit",
    "aws_bedrock_invocation": "AWS Bedrock",
    "azure_activity": "Azure Activity log",
    "azure_audit": "Azure audit",
    "azure_monitor_activity": "Azure Monitor activity",
    "azure_pim": "Entra ID PIM",
    "entra_id_signin": "Entra ID sign-in logs",
    "entra_id_audit": "Entra ID audit logs",
    "azure_risk_detection": "Entra ID risk detections",
    "gcp_audit": "GCP Cloud Audit",
    "kubernetes_audit": "Kubernetes audit",
    "okta_system_log": "Okta System Log",
    "auth0_logs": "Auth0 logs",
    "duo_activity": "Duo activity",
    "onelogin_events": "OneLogin events",
    "google_workspace_audit": "Google Workspace audit",
    "m365_audit": "Microsoft 365 audit",
    "m365_exchange_audit": "Exchange Online audit",
    "microsoft365_exchange_audit": "Exchange Online audit",
    "microsoft365_sharepoint_audit": "SharePoint Online audit",
    "m365_defender": "Microsoft 365 Defender",
    "microsoft_defender_xdr": "Defender XDR",
    "microsoft_intune_audit": "Intune audit",
    "github_audit": "GitHub audit log",
    "github_webhook": "GitHub webhooks",
    "gitlab_audit": "GitLab audit",
    "bitbucket_audit": "Bitbucket audit",
    "atlassian_audit": "Atlassian audit",
    "slack_audit": "Slack audit",
    "snyk_org_audit": "Snyk audit",
    "cyberark_audit": "CyberArk audit",
    "database_logs": "Database logs",
    "siem_alert": "SIEM alerts",
}


def data_source_label(name: str) -> str:
    return DATA_SOURCE_LABELS.get(name) or name.replace("_", " ").capitalize()


_RESOURCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,40}$")


def _is_resource_type(value: str) -> bool:
    """Type-shaped resource values: short lowercase tokens like
    `bucket`, `pods`, `gcs_bucket`. Excludes names (GUIDs start with a
    digit or carry uppercase/spaces, ARNs carry colons, field names
    carry dots/camelCase) and one-off junk."""
    return bool(_RESOURCE_TYPE_RE.fullmatch(value))


def _column(kind: str):
    return getattr(Detection, OBSERVABLE_TYPES[kind][0])


def _contains(kind: str, value: str):
    escaped = value.replace("%", "\\%").replace("_", "\\_")
    return cast(_column(kind), String).ilike(f'%"{escaped}"%', escape="\\")


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
_IPV6_RE = re.compile(r"^[0-9a-f:]+:[0-9a-f:]*(?:/\d{1,3})?$", re.IGNORECASE)
_URL_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|www\.)|/", re.IGNORECASE)

NETWORK_SHAPES: dict[str, str] = {
    "ip": "IP addresses and ranges",
    "port": "Ports",
    "domain": "Domains and hostnames",
    "url": "URLs and paths",
}


def network_shape(value: str) -> str:
    """Which kind of network indicator a value is, from its shape."""
    v = value.strip().strip("*")
    if v.isdigit() and 0 < int(v) <= 65535:
        return "port"
    if _IPV4_RE.match(v) or _IPV6_RE.match(v):
        return "ip"
    if _URL_RE.search(v):
        return "url"
    return "domain"


async def top_values(
    db: AsyncSession, kind: str, limit: int = 100, source: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    """Most common values on one surface, with rule + source counts.

    `q` filters values by case-insensitive substring so the index can
    be searched (4,000+ distinct process names do not fit a top list).
    """
    query = select(Detection.source, _column(kind), Detection.data_sources)
    if source:
        query = query.where(Detection.source == source)
    rows = (await db.execute(query)).all()
    counts: Counter[str] = Counter()
    by_source: dict[str, Counter[str]] = defaultdict(Counter)
    by_data_source: dict[str, Counter[str]] = defaultdict(Counter)
    canonical: dict[str, str] = {}
    needle = (q or "").strip().lower()
    for src, values, data_sources in rows:
        # A rule naming the same value twice counts once.
        for v in {v.lower(): v for v in (values or []) if isinstance(v, str) and v.strip()}.values():
            # Resource index carries TYPES only (#60): "which rules
            # watch buckets / roles / pods". Specific resource names
            # (GUIDs, "Okta Admin Console", ARNs) are per-rule detail,
            # visible on each rule page, and only muddied the list.
            if kind == "resource" and not _is_resource_type(v):
                continue
            key = v.lower()
            if needle and needle not in key:
                continue
            canonical.setdefault(key, v)
            counts[key] += 1
            by_source[key][src] += 1
            for ds in data_sources or []:
                if isinstance(ds, str) and ds and ds != "unknown":
                    by_data_source[key][ds] += 1
    return {
        "type": kind,
        "label": OBSERVABLE_TYPES[kind][2],
        "distinct": len(counts),
        "query": needle or None,
        "values": [
            {
                "value": canonical[k],
                "rules": n,
                "sources": sorted(by_source[k]),
                # {source: rule_count} so the UI can label the breakdown.
                "by_source": dict(sorted(by_source[k].items(), key=lambda kv: (-kv[1], kv[0]))),
                # What the value means where we know (event IDs: the
                # log channel / provider the ID belongs to).
                "context": _context(kind, canonical[k], by_data_source[k]),
            }
            for k, n in counts.most_common(limit)
        ],
    }


def _context(kind: str, value: str, data_sources: Counter[str]) -> Optional[dict]:
    """What a value belongs to. Event IDs: the Windows log from the
    dictionary. API actions: the audit log the rules using it read
    (their dominant canonical data source), so "ConsoleLogin" says AWS
    CloudTrail and "user.session.start" says Okta System Log without
    the reader having to know."""
    if kind == "eventid":
        entry = lookup_event_id(value)
        if entry is not None:
            return {"label": entry.label, "provider": entry.provider, "channel": entry.channel}
        auth0 = lookup_auth0_event(value)
        if auth0 is not None:
            return {"label": auth0.label, "provider": "auth0", "channel": "Auth0 log events"}
        return None
    if kind in ("action", "resource") and data_sources:
        ds, _n = data_sources.most_common(1)[0]
        label = data_source_label(ds)
        return {"label": label, "provider": ds, "channel": label}
    if kind == "network":
        shape = network_shape(value)
        return {"label": NETWORK_SHAPES[shape], "provider": shape, "channel": NETWORK_SHAPES[shape]}
    return None


async def observable_profile(db: AsyncSession, kind: str, value: str, sample_limit: int = 50) -> dict:
    rows = (
        await db.execute(
            select(
                Detection.id, Detection.title, Detection.source, Detection.severity, Detection.status,
                Detection.mitre_techniques, Detection.mitre_tactics, Detection.platforms,
                Detection.quality_score, Detection.rule_created_date,
                *[_column(k) for k in _CO_OCCUR_SURFACES],
                Detection.extracted_observables,
            ).where(_contains(kind, value)).order_by(Detection.source.asc(), Detection.title.asc())
        )
    ).all()

    by_source: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_technique: Counter[str] = Counter()
    by_tactic: Counter[str] = Counter()
    by_platform: Counter[str] = Counter()
    co: dict[str, Counter[str]] = {k: Counter() for k in _CO_OCCUR_SURFACES}
    negated_in = 0
    fields: Counter[str] = Counter()
    samples: list[dict] = []
    value_l = value.lower()

    for r in rows:
        rid, title, source, severity, status, techs, tactics, platforms, quality, created = r[:10]
        by_source[source] += 1
        by_severity[severity or "unknown"] += 1
        for t in techs or []:
            by_technique[t] += 1
        for t in tactics or []:
            by_tactic[t] += 1
        for p in platforms or []:
            if p and p != "unknown":
                by_platform[p] += 1
        for k, vals in zip(_CO_OCCUR_SURFACES, r[10:10 + len(_CO_OCCUR_SURFACES)]):
            for v in vals or []:
                if isinstance(v, str) and v and not (k == kind and v.lower() == value_l):
                    co[k][v] += 1
        # Which field named it, and whether any rule uses it as an exclusion.
        for o in r[10 + len(_CO_OCCUR_SURFACES)] or []:
            if not isinstance(o, dict):
                continue
            if any(isinstance(x, str) and x.lower() == value_l for x in (o.get("values") or [])):
                fields[o.get("field") or "?"] += 1
                if o.get("negated"):
                    negated_in += 1
                    break
        if len(samples) < sample_limit:
            samples.append({
                "id": rid, "title": title, "source": source, "severity": severity, "status": status,
                "mitre_techniques": techs or [], "quality_score": quality,
                "created": created.isoformat() + "Z" if created else None,
            })

    col, filter_key, label = OBSERVABLE_TYPES[kind]
    return {
        "type": kind,
        "label": label,
        "value": value,
        "filter_key": filter_key,
        "total_rules": len(rows),
        "negated_in": negated_in,
        "by_source": dict(by_source.most_common()),
        "by_severity": dict(by_severity.most_common()),
        "by_platform": dict(by_platform.most_common(8)),
        "by_technique": [{"technique_id": t, "rules": n} for t, n in by_technique.most_common(15)],
        "by_tactic": [{"tactic_id": t, "rules": n} for t, n in by_tactic.most_common(8)],
        "fields": [{"field": f, "rules": n} for f, n in fields.most_common(8)],
        "co_occurring": {
            k: [{"value": v, "rules": n} for v, n in c.most_common(8)]
            for k, c in co.items() if c
        },
        "rules": samples,
    }


async def count_rules(db: AsyncSession, kind: str, value: str) -> int:
    return (await db.execute(select(func.count(Detection.id)).where(_contains(kind, value)))).scalar() or 0
