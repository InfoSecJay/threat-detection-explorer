"""Trending data API routes."""

import re
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, String, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.repository_sync import ALL_REPOSITORY_NAMES

router = APIRouter(prefix="/trending", tags=["trending"])


def _parse_csv(raw: Optional[str]) -> list[str]:
    """Split a comma-separated query value into a trimmed list."""
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _apply_trending_filters(
    conditions: list,
    sources: list[str],
    platforms: list[str],
    event_types: list[str],
) -> None:
    """Append source / platform / event-type filters to a condition list.

    Shared between all three trending endpoints so the filter semantics
    stay identical: source is an exact-match on the enum column, while
    platform + event_type use the same JSON-array `ilike` trick the
    search service uses (portable across SQLite + Postgres).
    """
    if sources:
        conditions.append(Detection.source.in_(sources))
    if platforms:
        plat_conds = [
            cast(Detection.taxonomy_platforms, String).ilike(f'%"{v}"%')
            for v in platforms
        ]
        conditions.append(or_(*plat_conds))
    if event_types:
        et_conds = [
            cast(Detection.taxonomy_event_types, String).ilike(f'%"{v}"%')
            for v in event_types
        ]
        conditions.append(or_(*et_conds))


@router.get("/techniques")
async def get_trending_techniques(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of techniques to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    platforms: Optional[str] = Query(None, description="Comma-separated canonical-platform filter (e.g. 'o365,windows')"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Get trending MITRE techniques based on recently created/modified rules.

    Returns techniques ordered by the number of rules created/modified in the time period.
    Optional filters narrow the corpus before counting (e.g. "top techniques in new O365 rules").
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), _parse_csv(platforms), _parse_csv(event_types))

    query = select(Detection).where(and_(*conditions))

    result = await db.execute(query)
    detections = result.scalars().all()

    # Count techniques
    technique_counts: dict[str, dict] = {}
    for detection in detections:
        for technique in detection.mitre_techniques:
            if technique not in technique_counts:
                technique_counts[technique] = {
                    "technique_id": technique,
                    "count": 0,
                    "sources": set(),
                    "latest_date": None,
                }
            technique_counts[technique]["count"] += 1
            technique_counts[technique]["sources"].add(detection.source)

            # Track the most recent rule date for this technique
            if detection.rule_modified_date:
                current_latest = technique_counts[technique]["latest_date"]
                if current_latest is None or detection.rule_modified_date > current_latest:
                    technique_counts[technique]["latest_date"] = detection.rule_modified_date

    # Sort by count and return top N
    sorted_techniques = sorted(
        technique_counts.values(),
        key=lambda x: (-x["count"], x["technique_id"]),
    )[:limit]

    # Convert sets to lists and format dates
    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "count": t["count"],
                "sources": list(t["sources"]),
                "latest_date": t["latest_date"].isoformat() if t["latest_date"] else None,
            }
            for t in sorted_techniques
        ],
    }


@router.get("/platforms")
async def get_trending_platforms(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of platforms to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Get trending platforms based on recently created/modified rules.

    Reads the canonical `taxonomy_platforms` array column so multi-OS
    rules count toward every platform they target (a rule tagged
    [windows, linux] counts for both). The `unknown` sentinel is
    filtered out so it doesn't dominate. Note: a `platforms` filter
    here would be circular (it's the grouping key), so only source +
    event_type are exposed.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), [], _parse_csv(event_types))

    query = select(Detection).where(and_(*conditions))

    result = await db.execute(query)
    detections = result.scalars().all()

    platform_counts: dict[str, dict] = {}
    for detection in detections:
        platforms = detection.taxonomy_platforms or []
        for platform in platforms:
            if not platform or platform == "unknown":
                continue
            if platform not in platform_counts:
                platform_counts[platform] = {
                    "platform": platform,
                    "count": 0,
                    "sources": set(),
                    "latest_date": None,
                }
            platform_counts[platform]["count"] += 1
            platform_counts[platform]["sources"].add(detection.source)

            if detection.rule_modified_date:
                current_latest = platform_counts[platform]["latest_date"]
                if current_latest is None or detection.rule_modified_date > current_latest:
                    platform_counts[platform]["latest_date"] = detection.rule_modified_date

    sorted_platforms = sorted(
        platform_counts.values(),
        key=lambda x: (-x["count"], x["platform"]),
    )[:limit]

    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "platforms": [
            {
                "platform": p["platform"],
                "count": p["count"],
                "sources": list(p["sources"]),
                "latest_date": p["latest_date"].isoformat() if p["latest_date"] else None,
            }
            for p in sorted_platforms
        ],
    }


@router.get("/recent-rules")
async def get_recent_rules(
    limit: int = Query(20, ge=5, le=50, description="Number of rules per list"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    platforms: Optional[str] = Query(None, description="Comma-separated canonical-platform filter (e.g. 'o365,windows')"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Return the most recently created + most recently modified rules.

    Two parallel lists, each ordered by the respective date descending.
    Powers the "Recent activity" section of the Intel page. Rules
    without a date stamp are excluded (would pollute the top of the
    list with deterministic-but-meaningless ordering). Optional filters
    narrow the corpus (e.g. sources=sigma&platforms=o365).
    """
    def _format(d: Detection, date_field: str) -> dict:
        date_value = getattr(d, date_field, None)
        return {
            "id": d.id,
            "rule_id": d.rule_id,
            "title": d.title,
            "source": d.source,
            "severity": d.severity,
            "platforms": d.taxonomy_platforms or [],
            "event_types": d.taxonomy_event_types or [],
            "date": date_value.isoformat() if date_value else None,
        }

    src_list = _parse_csv(sources)
    plat_list = _parse_csv(platforms)
    et_list = _parse_csv(event_types)

    created_conds = [Detection.rule_created_date.isnot(None)]
    _apply_trending_filters(created_conds, src_list, plat_list, et_list)
    created_q = (
        select(Detection)
        .where(and_(*created_conds))
        .order_by(Detection.rule_created_date.desc())
        .limit(limit)
    )

    modified_conds = [Detection.rule_modified_date.isnot(None)]
    _apply_trending_filters(modified_conds, src_list, plat_list, et_list)
    modified_q = (
        select(Detection)
        .where(and_(*modified_conds))
        .order_by(Detection.rule_modified_date.desc())
        .limit(limit)
    )

    created = (await db.execute(created_q)).scalars().all()
    modified = (await db.execute(modified_q)).scalars().all()

    return {
        "most_recently_created": [_format(d, "rule_created_date") for d in created],
        "most_recently_modified": [_format(d, "rule_modified_date") for d in modified],
    }


@router.get("/summary")
async def get_trending_summary(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    db: AsyncSession = Depends(get_db),
):
    """Get a summary of recent activity across all sources."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Count total rules modified in period
    total_query = select(func.count(Detection.id)).where(
        and_(
            Detection.rule_modified_date.isnot(None),
            Detection.rule_modified_date >= cutoff_date,
        )
    )
    total_result = await db.execute(total_query)
    total_modified = total_result.scalar() or 0

    # Count by source
    by_source = {}
    for source in ALL_REPOSITORY_NAMES:
        source_query = select(func.count(Detection.id)).where(
            and_(
                Detection.source == source,
                Detection.rule_modified_date.isnot(None),
                Detection.rule_modified_date >= cutoff_date,
            )
        )
        source_result = await db.execute(source_query)
        count = source_result.scalar() or 0
        if count > 0:
            by_source[source] = count

    return {
        "period_days": days,
        "cutoff_date": cutoff_date.isoformat(),
        "total_modified": total_modified,
        "by_source": by_source,
    }


# ── Threat pulse ─────────────────────────────────────────────────────────
# Named threats come from vendor-specific "story" tags our parsers emit:
#   Splunk's `analytic_story` → tag prefix `story:<snake_case>`
#   Sublime's `Malfam:<Name>` tag is preserved as-is
# CVEs are regex-extracted from tags + title + description across all
# sources. Sigma stores them dot-separated (`cve.2021-1675`) so the regex
# has to accept either `-` or `.` as the separator, then normalize.
#
# NOTHING in this module hardcodes specific threat names. The threat
# denylist below only suppresses generic TTP categories; named threats
# (campaigns, APT groups, malware families) flow through dynamically
# as vendors publish new ones.

CVE_RE = re.compile(r"CVE[.\-](\d{4})[.\-](\d{4,7})", re.IGNORECASE)

# Generic categories that Splunk publishes as `analytic_story` values
# but describe a TTP / kill-chain / platform rather than a specific
# campaign. Suppressing them keeps the "what's the industry watching"
# list tight and focused on named threats.
GENERIC_SPLUNK_STORIES: set[str] = {
    # Single-word category/platform tags
    "endpoint", "network", "identity", "threat", "ransomware",
    "kubernetes", "web_application", "web_server",
    # Compromised-* generic hosts/accounts
    "compromised_windows_host", "compromised_linux_host",
    "compromised_user_account",
    # Technique / kill-chain categories
    "living_off_the_land", "data_destruction", "data_exfiltration",
    "credential_dumping", "command_and_control",
    "scheduled_tasks", "malicious_powershell",
    "windows_registry_abuse", "windows_defense_evasion_tactics",
    "windows_persistence_techniques", "windows_discovery_techniques",
    "linux_persistence_techniques", "linux_living_off_the_land",
    "linux_privilege_escalation", "linux_discovery",
    "linux_post-exploitation", "windows_post-exploitation",
    "active_directory_discovery", "active_directory_lateral_movement",
    "active_directory_kerberos_attacks",
    "active_directory_persistence", "active_directory_privilege_escalation",
    "active_directory_password_spraying",
    "spearphishing_attachments",
    # Cloud platform categories
    "o365_tenant", "aws_account", "azure_active_directory",
    "azure_active_directory_persistence",
    "azure_active_directory_account_takeover",
    "office_365_account_takeover",
    "cloud_federated_credential_abuse",
    "okta_account_takeover", "kubernetes_security",
    "cloud_cryptomining", "container_and_kubernetes",
}

# Splunk's `asset_type` and `security_domain` values. The Splunk
# normalizer currently flattens ALL tag prefixes (`story:`, `asset:`,
# `domain:`) into bare values — so in the DB a Splunk tag has lost the
# hint that told us which bucket it came from. We identify story tags
# by elimination: anything that isn't in this finite asset/domain set
# and isn't a generic category is treated as an analytic_story.
SPLUNK_ASSET_DOMAIN_TAGS: set[str] = {
    "endpoint", "network", "host", "cloud", "identity", "access",
    "application", "database", "threat", "audit", "infrastructure",
    "compliance", "security",
}


def _extract_cves(text: str) -> set[str]:
    """Return the set of normalized CVE ids found in ``text``."""
    if not text:
        return set()
    return {f"CVE-{m.group(1)}-{m.group(2)}" for m in CVE_RE.finditer(text)}


def _story_display(raw: str) -> Optional[tuple[str, str]]:
    """Transform a raw Splunk story slug into (display_name, 'campaign').

    Returns None for generic TTP categories. Uppercasing just the first
    character preserves internal punctuation ($) and digits (aa23-347a)
    that ``str.capitalize`` would mangle.
    """
    if not raw or raw in GENERIC_SPLUNK_STORIES:
        return None
    display = " ".join(
        (w[:1].upper() + w[1:]) if w else w
        for w in raw.replace("_", " ").split()
    )
    return (display, "campaign") if display else None


def _extract_named_threat(tag: str, source: str) -> Optional[tuple[str, str]]:
    """Return ``(display_name, kind)`` if the tag names a specific threat.

    Returns None for generic categories, structural tags, or anything
    we don't recognize as a vendor-authored threat identifier.
    """
    # Prefixed formats (future-proof: once the Splunk normalizer is
    # fixed to preserve `story:` this branch kicks in).
    if tag.startswith("story:"):
        return _story_display(tag[len("story:"):].lower().strip())
    if tag.startswith("Malfam:"):
        name = tag[len("Malfam:"):].strip()
        return (name, "malware") if name else None

    # Splunk today: prefixes stripped by the normalizer. Any bare tag
    # that isn't a known asset/domain value is treated as a story.
    if source == "splunk":
        t = tag.lower().strip()
        if t and t not in SPLUNK_ASSET_DOMAIN_TAGS:
            return _story_display(t)
    return None


@router.get("/threats")
async def get_threat_pulse(
    limit: int = Query(8, ge=3, le=30, description="Items per list"),
    db: AsyncSession = Depends(get_db),
):
    """Industry threat pulse: named threats + newly covered CVEs.

    Surfaces what vendors are actively writing detections for. Named
    threats come from per-vendor story tags (Splunk `analytic_story`,
    Sublime `Malfam:`). CVEs are regex-extracted across tags, title,
    and description from every source.

    Scans the full corpus — NOT filtered by ``rule_modified_date`` —
    because that column is only populated for Elastic + Sigma today
    (Splunk, Sentinel, Sublime, Elastic Protections/Hunting parsers
    don't extract a modified date yet). Filtering would silently drop
    every Splunk ``analytic_story`` tag. Roadmap item: backfill parser
    date extraction, then re-introduce a time window here.
    """
    # Only pull columns we actually scan — detection_logic is large
    # and irrelevant to threat-name extraction.
    q = select(
        Detection.id,
        Detection.source,
        Detection.title,
        Detection.description,
        Detection.tags,
    )
    rows = (await db.execute(q)).all()

    threats: dict[str, dict] = {}
    cves: dict[str, dict] = {}

    def _add_example(entry: dict, rule_id: str, title: str, source: str) -> None:
        if len(entry["examples"]) < 3:
            entry["examples"].append({"id": rule_id, "title": title, "source": source})

    for rule_id, source, title, description, tags in rows:
        tag_list = tags or []

        # Named threats from recognized tag prefixes / Splunk bare tags
        for tag in tag_list:
            if not isinstance(tag, str):
                continue
            hit = _extract_named_threat(tag, source)
            if hit is None:
                continue
            name, kind = hit
            entry = threats.setdefault(
                name,
                {"name": name, "kind": kind, "count": 0, "sources": set(), "examples": []},
            )
            entry["count"] += 1
            entry["sources"].add(source)
            _add_example(entry, rule_id, title or "", source)

        # CVEs anywhere in tag/title/description for this rule. We
        # dedupe per-rule so a rule that mentions the same CVE three
        # times only contributes +1 to its count.
        cve_blob = " ".join([
            " ".join(t for t in tag_list if isinstance(t, str)),
            title or "",
            description or "",
        ])
        for cve in _extract_cves(cve_blob):
            entry = cves.setdefault(
                cve,
                {"cve": cve, "count": 0, "sources": set(), "examples": []},
            )
            entry["count"] += 1
            entry["sources"].add(source)
            _add_example(entry, rule_id, title or "", source)

    sorted_threats = sorted(threats.values(), key=lambda x: (-x["count"], x["name"]))[:limit]
    sorted_cves = sorted(cves.values(), key=lambda x: (-x["count"], x["cve"]))[:limit]

    return {
        "period_days": days,
        "cutoff_date": cutoff.isoformat(),
        "named_threats": [
            {**t, "sources": sorted(t["sources"])} for t in sorted_threats
        ],
        "cves": [
            {**c, "sources": sorted(c["sources"])} for c in sorted_cves
        ],
    }
