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
from app.utils.datetime_utils import to_utc_iso, utcnow

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
            cast(Detection.platforms, String).ilike(f'%"{v}"%')
            for v in platforms
        ]
        conditions.append(or_(*plat_conds))
    if event_types:
        et_conds = [
            cast(Detection.event_types, String).ilike(f'%"{v}"%')
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
    cutoff_date = utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), _parse_csv(platforms), _parse_csv(event_types))

    # Column-scoped query: avoid loading detection_logic / raw_content /
    # the dozen extracted_* JSON columns we never read here.
    query = select(
        Detection.source,
        Detection.mitre_techniques,
        Detection.rule_modified_date,
    ).where(and_(*conditions))

    rows = (await db.execute(query)).all()

    technique_counts: dict[str, dict] = {}
    for source, techniques, modified_date in rows:
        if not techniques:
            continue
        for technique in techniques:
            if technique not in technique_counts:
                technique_counts[technique] = {
                    "technique_id": technique,
                    "count": 0,
                    "sources": set(),
                    "latest_date": None,
                }
            technique_counts[technique]["count"] += 1
            technique_counts[technique]["sources"].add(source)

            if modified_date:
                current_latest = technique_counts[technique]["latest_date"]
                if current_latest is None or modified_date > current_latest:
                    technique_counts[technique]["latest_date"] = modified_date

    # Sort by count and return top N
    sorted_techniques = sorted(
        technique_counts.values(),
        key=lambda x: (-x["count"], x["technique_id"]),
    )[:limit]

    # Convert sets to lists and format dates
    return {
        "period_days": days,
        "cutoff_date": to_utc_iso(cutoff_date),
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "count": t["count"],
                "sources": list(t["sources"]),
                "latest_date": to_utc_iso(t["latest_date"]),
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

    Reads the canonical `platforms` array column so multi-OS
    rules count toward every platform they target (a rule tagged
    [windows, linux] counts for both). The `unknown` sentinel is
    filtered out so it doesn't dominate. Note: a `platforms` filter
    here would be circular (it's the grouping key), so only source +
    event_type are exposed.
    """
    cutoff_date = utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), [], _parse_csv(event_types))

    query = select(
        Detection.source,
        Detection.platforms,
        Detection.rule_modified_date,
    ).where(and_(*conditions))

    rows = (await db.execute(query)).all()

    platform_counts: dict[str, dict] = {}
    for source, platforms_list, modified_date in rows:
        for platform in platforms_list or []:
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
            platform_counts[platform]["sources"].add(source)

            if modified_date:
                current_latest = platform_counts[platform]["latest_date"]
                if current_latest is None or modified_date > current_latest:
                    platform_counts[platform]["latest_date"] = modified_date

    sorted_platforms = sorted(
        platform_counts.values(),
        key=lambda x: (-x["count"], x["platform"]),
    )[:limit]

    return {
        "period_days": days,
        "cutoff_date": to_utc_iso(cutoff_date),
        "platforms": [
            {
                "platform": p["platform"],
                "count": p["count"],
                "sources": list(p["sources"]),
                "latest_date": to_utc_iso(p["latest_date"]),
            }
            for p in sorted_platforms
        ],
    }


@router.get("/recent-rules")
async def get_recent_rules(
    limit: int = Query(20, ge=5, le=50, description="Number of rules per list"),
    days: Optional[int] = Query(
        None,
        ge=1,
        le=365,
        description=(
            "Optional lookback window. When set, only rules with a "
            "created/modified date within the window are returned. "
            "Omit for the unbounded 'most recent N' behavior."
        ),
    ),
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

    Pass ``days=N`` to hard-cap the window — that scoping is what the
    Intel page's global period toggle relies on.
    """
    # Column-scoped: only what _format() actually reads. Skips
    # detection_logic, raw_content, and the extracted_* JSON columns
    # which are large and never used for the activity strip.
    columns = (
        Detection.id,
        Detection.rule_id,
        Detection.title,
        Detection.source,
        Detection.severity,
        Detection.platforms,
        Detection.event_types,
        Detection.rule_created_date,
        Detection.rule_modified_date,
    )

    def _format(row, date_index: int) -> dict:
        date_value = row[date_index]
        return {
            "id": row[0],
            "rule_id": row[1],
            "title": row[2],
            "source": row[3],
            "severity": row[4],
            "platforms": row[5] or [],
            "event_types": row[6] or [],
            "date": to_utc_iso(date_value),
        }

    src_list = _parse_csv(sources)
    plat_list = _parse_csv(platforms)
    et_list = _parse_csv(event_types)
    cutoff = utcnow() - timedelta(days=days) if days is not None else None

    created_conds = [Detection.rule_created_date.isnot(None)]
    if cutoff is not None:
        created_conds.append(Detection.rule_created_date >= cutoff)
    _apply_trending_filters(created_conds, src_list, plat_list, et_list)
    created_q = (
        select(*columns)
        .where(and_(*created_conds))
        .order_by(Detection.rule_created_date.desc())
        .limit(limit)
    )

    modified_conds = [Detection.rule_modified_date.isnot(None)]
    if cutoff is not None:
        modified_conds.append(Detection.rule_modified_date >= cutoff)
    _apply_trending_filters(modified_conds, src_list, plat_list, et_list)
    modified_q = (
        select(*columns)
        .where(and_(*modified_conds))
        .order_by(Detection.rule_modified_date.desc())
        .limit(limit)
    )

    created = (await db.execute(created_q)).all()
    modified = (await db.execute(modified_q)).all()

    # rule_created_date is column index 7, rule_modified_date is 8
    return {
        "most_recently_created": [_format(r, 7) for r in created],
        "most_recently_modified": [_format(r, 8) for r in modified],
    }


@router.get("/summary")
async def get_trending_summary(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    db: AsyncSession = Depends(get_db),
):
    """Recent-activity summary — created + modified counts across sources.

    Splits the tally into two columns so callers can distinguish real new
    content from hygiene bumps (a repo that only re-touches existing
    rules shows large `modified` and near-zero `created`). Zero-activity
    sources are omitted from `by_source` to keep the payload lean.
    """
    cutoff_date = utcnow() - timedelta(days=days)

    async def _count(col) -> int:
        result = await db.execute(
            select(func.count(Detection.id)).where(
                and_(col.isnot(None), col >= cutoff_date)
            )
        )
        return result.scalar() or 0

    total_created = await _count(Detection.rule_created_date)
    total_modified = await _count(Detection.rule_modified_date)

    by_source: dict[str, dict[str, int]] = {}
    for source in ALL_REPOSITORY_NAMES:
        created_q = select(func.count(Detection.id)).where(
            and_(
                Detection.source == source,
                Detection.rule_created_date.isnot(None),
                Detection.rule_created_date >= cutoff_date,
            )
        )
        modified_q = select(func.count(Detection.id)).where(
            and_(
                Detection.source == source,
                Detection.rule_modified_date.isnot(None),
                Detection.rule_modified_date >= cutoff_date,
            )
        )
        created = (await db.execute(created_q)).scalar() or 0
        modified = (await db.execute(modified_q)).scalar() or 0
        if created or modified:
            by_source[source] = {"created": created, "modified": modified}

    return {
        "period_days": days,
        "cutoff_date": to_utc_iso(cutoff_date),
        "total_created": total_created,
        "total_modified": total_modified,
        "by_source": by_source,
    }


@router.get("/use-cases")
async def get_trending_use_cases(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of use cases to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    platforms: Optional[str] = Query(None, description="Comma-separated canonical-platform filter"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Top vendor use-cases / analytic stories in-window.

    Mirrors ``/trending/techniques`` but groups by the ``use_cases``
    JSON array column. Answers "what themes are vendors writing about
    right now?" — a rule tagged with two analytic stories counts toward
    both. Empty use_cases are ignored.
    """
    cutoff_date = utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_modified_date.isnot(None),
        Detection.rule_modified_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), _parse_csv(platforms), _parse_csv(event_types))

    query = select(
        Detection.source,
        Detection.use_cases,
        Detection.rule_modified_date,
    ).where(and_(*conditions))

    rows = (await db.execute(query)).all()

    counts: dict[str, dict] = {}
    for source, use_cases, modified_date in rows:
        if not use_cases:
            continue
        for uc in use_cases:
            if not uc:
                continue
            entry = counts.setdefault(
                uc,
                {"use_case": uc, "count": 0, "sources": set(), "latest_date": None},
            )
            entry["count"] += 1
            entry["sources"].add(source)
            if modified_date:
                if entry["latest_date"] is None or modified_date > entry["latest_date"]:
                    entry["latest_date"] = modified_date

    sorted_counts = sorted(counts.values(), key=lambda x: (-x["count"], x["use_case"]))[:limit]

    return {
        "period_days": days,
        "cutoff_date": to_utc_iso(cutoff_date),
        "use_cases": [
            {
                "use_case": c["use_case"],
                "count": c["count"],
                "sources": sorted(c["sources"]),
                "latest_date": to_utc_iso(c["latest_date"]),
            }
            for c in sorted_counts
        ],
    }


@router.get("/weekly-activity")
async def get_weekly_activity(
    weeks: int = Query(12, ge=4, le=52, description="Number of weeks of history"),
    db: AsyncSession = Depends(get_db),
):
    """Per-source rules-created-per-week for sparklines on Repo Health.

    Returns ``weeks`` buckets ending on the current ISO week, each with
    a per-source count of rules whose ``rule_created_date`` falls in that
    bucket. Portable across SQLite + Postgres: buckets are computed in
    Python from ``(source, rule_created_date)`` rows to avoid SQL
    date-truncation dialect differences.

    Only counts CREATED rules (not modified) so the sparkline tracks
    genuine new content, not hygiene passes.
    """
    now = utcnow()
    # ISO week start: Monday. Truncate now to this week's Monday, midnight UTC.
    days_since_monday = now.weekday()
    this_week_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days_since_monday)

    # Build week-start list oldest → newest so the sparkline reads L-to-R.
    week_starts = [this_week_start - timedelta(weeks=(weeks - 1 - i)) for i in range(weeks)]
    oldest_cutoff = week_starts[0]

    query = select(Detection.source, Detection.rule_created_date).where(
        and_(
            Detection.rule_created_date.isnot(None),
            Detection.rule_created_date >= oldest_cutoff,
        )
    )
    rows = (await db.execute(query)).all()

    def _bucket_index(dt) -> Optional[int]:
        """Return which week bucket a date belongs to, or None if out of range."""
        if dt is None or dt < oldest_cutoff:
            return None
        # Integer weeks since the oldest bucket start.
        delta_days = (dt - oldest_cutoff).days
        idx = delta_days // 7
        return idx if 0 <= idx < weeks else None

    by_source: dict[str, list[int]] = {name: [0] * weeks for name in ALL_REPOSITORY_NAMES}
    for source, created_date in rows:
        idx = _bucket_index(created_date)
        if idx is None or source not in by_source:
            continue
        by_source[source][idx] += 1

    # Drop sources with no activity at all in the window so the payload
    # stays tight — the FE can render "no data" for repos not included.
    by_source_filtered = {k: v for k, v in by_source.items() if any(v)}

    return {
        "weeks": weeks,
        "week_starts": [w.date().isoformat() for w in week_starts],
        "by_source": by_source_filtered,
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


@router.get("/newly-covered")
async def get_newly_covered(
    days: int = Query(30, ge=7, le=365, description="Diff window in days"),
    limit: int = Query(50, ge=5, le=200, description="Cap per list"),
    sources: Optional[str] = Query(
        None, description="Comma-separated source filter (source list only)"
    ),
    db: AsyncSession = Depends(get_db),
):
    """MITRE coverage diff — the "just covered" signal (issue #9).

    Two lists: techniques that gained their FIRST rule catalog-wide
    inside the window, and techniques an individual source just picked
    up while others already covered them ("Splunk just picked up
    T1651 — Sigma's had it for two years").

    `method` tells the caller how the diff was computed: "snapshot"
    (exact — daily mitre_coverage_snapshot rows exist at least `days`
    back) or "rule_dates" (git-derived first-rule dates, used until
    snapshot history accumulates). Sources onboarded inside the window
    are listed under `new_sources` rather than flooding the
    per-source list.
    """
    from app.services.coverage_snapshot import compute_newly_covered

    return await compute_newly_covered(
        db,
        days=days,
        limit=limit,
        sources=_parse_csv(sources) or None,
    )


@router.get("/threats")
async def get_threat_pulse(
    limit: int = Query(8, ge=3, le=30, description="Items per list"),
    days: Optional[int] = Query(
        None,
        ge=7,
        le=730,
        description=(
            "Optional lookback window in days. When set, only rules with "
            "rule_modified_date OR rule_created_date within the window "
            "contribute. Omit for a full-catalog scan (default)."
        ),
    ),
    db: AsyncSession = Depends(get_db),
):
    """Industry threat pulse: named threats + newly covered CVEs.

    Surfaces what vendors are actively writing detections for. Named
    threats come from per-vendor story tags (Splunk `analytic_story`,
    Sublime `Malfam:`). CVEs are regex-extracted across tags, title,
    and description from every source.

    By default scans the full corpus (no time filter). Pass ``days=N``
    to constrain to rules touched in the window — useful for the "what
    is the industry watching RIGHT NOW" framing on the Intel page. The
    filter accepts a hit on either ``rule_modified_date`` or
    ``rule_created_date``: a rule that was created last week with no
    later edits should still count as recent activity.
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
    if days is not None:
        cutoff = utcnow() - timedelta(days=days)
        # Hit on either modified or created — rules created in-window
        # with no later edits should still count as recent activity.
        q = q.where(
            or_(
                Detection.rule_modified_date >= cutoff,
                Detection.rule_created_date >= cutoff,
            )
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
        "scope": "window" if days is not None else "full_catalog",
        "period_days": days,
        "named_threats": [
            {**t, "sources": sorted(t["sources"])} for t in sorted_threats
        ],
        "cves": [
            {**c, "sources": sorted(c["sources"])} for c in sorted_cves
        ],
    }


@router.get("/source-deltas")
async def get_source_deltas(
    days: int = Query(7, ge=1, le=90, description="Delta window in days"),
    db: AsyncSession = Depends(get_db),
):
    """Net rule-count change per source over the window (issue #19).

    Derived from completed whole-corpus sync jobs: each stores every
    source's corpus size that night, so "latest minus the newest job at
    least `days` old" is an exact net delta (additions minus removals),
    which git-derived created dates cannot give. `method` is
    `sync_jobs` (exact), `insufficient_history` (no baseline old enough
    yet; only `current` populated) or `no_data`.
    """
    from app.services.source_deltas import compute_source_deltas

    return await compute_source_deltas(db, days=days)


@router.get("/data-sources")
async def get_trending_data_sources(
    days: int = Query(90, ge=7, le=365, description="Number of days to look back"),
    limit: int = Query(15, ge=5, le=50, description="Number of data sources to return"),
    sources: Optional[str] = Query(None, description="Comma-separated source filter"),
    event_types: Optional[str] = Query(None, description="Comma-separated canonical-event-type filter"),
    db: AsyncSession = Depends(get_db),
):
    """Emerging data sources (issue #17): canonical `data_sources`
    ranked by NEW-rule volume in the window.

    Deliberately keyed on `rule_created_date`, not modified: the
    question is "where is new detection content being written", and a
    hygiene pass over old Windows rules must not read as Windows
    trending. Multi-source rules count toward every data source they
    read from; the `unknown` sentinel is dropped.
    """
    cutoff_date = utcnow() - timedelta(days=days)

    conditions = [
        Detection.rule_created_date.isnot(None),
        Detection.rule_created_date >= cutoff_date,
    ]
    _apply_trending_filters(conditions, _parse_csv(sources), [], _parse_csv(event_types))

    query = select(
        Detection.source,
        Detection.data_sources,
        Detection.rule_created_date,
    ).where(and_(*conditions))

    rows = (await db.execute(query)).all()

    counts: dict[str, dict] = {}
    for source, data_sources_list, created_date in rows:
        for ds in data_sources_list or []:
            if not isinstance(ds, str) or not ds or ds == "unknown":
                continue
            entry = counts.setdefault(
                ds, {"data_source": ds, "count": 0, "sources": set(), "latest_date": None},
            )
            entry["count"] += 1
            entry["sources"].add(source)
            if created_date and (entry["latest_date"] is None or created_date > entry["latest_date"]):
                entry["latest_date"] = created_date

    ranked = sorted(counts.values(), key=lambda x: (-x["count"], x["data_source"]))[:limit]

    return {
        "period_days": days,
        "cutoff_date": to_utc_iso(cutoff_date),
        "data_sources": [
            {
                "data_source": e["data_source"],
                "count": e["count"],
                "sources": sorted(e["sources"]),
                "latest_date": to_utc_iso(e["latest_date"]),
            }
            for e in ranked
        ],
    }


@router.get("/technique-deltas")
async def get_technique_deltas(
    days: int = Query(7, ge=1, le=90, description="Delta window in days"),
    limit: int = Query(10, ge=1, le=50, description="Cap per list"),
    db: AsyncSession = Depends(get_db),
):
    """Technique momentum (issue #19): catalog-wide rule-count change per
    ATT&CK technique between the latest coverage snapshot and the newest
    snapshot at least `days` old. Top gainers and losers, each with the
    sources that newly cover / dropped the technique. `method` is
    `snapshot`, `insufficient_history` (no baseline old enough yet) or
    `no_data`.
    """
    from app.services.technique_deltas import compute_technique_deltas

    return await compute_technique_deltas(db, days=days, limit=limit)
