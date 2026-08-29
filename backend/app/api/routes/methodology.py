"""Per-source counting methodology (issue #32).

Rule counts differ between aggregator sites because every site makes
different scope choices and none of them say so. This endpoint makes
ours legible: for each source, the upstream repo + branch, the exact
discovery globs and exclusions (read straight from the config the
ingester uses, so the doc cannot drift from the code), the sparse
checkout when there is one, the pinned commit and last sync time, and
a plain-English note on the scope decisions behind the number.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.repository import Repository
from app.services.repository_sync import (
    ALL_REPOSITORY_NAMES,
    SPARSE_CHECKOUT_BRANCHES,
    SPARSE_CHECKOUT_PATTERNS,
    RepositorySyncService,
)
from app.services.rule_discovery import RuleDiscoveryService
from app.utils.datetime_utils import to_utc_iso, utcnow

router = APIRouter(prefix="/methodology", tags=["methodology"])

# The human half of the methodology: WHY the globs are what they are.
# Keep each note to the decisions that move the count.
SCOPE_NOTES: dict[str, str] = {
    "sigma": (
        "rules/ plus every rules-*/ tree (emerging-threats, threat-hunting, "
        "compliance, dfir) is counted; deprecated/ and unsupported rules are "
        "not; rules-placeholder/ (stub rules with no logic) is excluded. "
        "Counts match a fresh clone of the same commit exactly."
    ),
    "elastic": (
        "rules/ and rules_building_block/ are both counted; building blocks "
        "are flagged is_building_block so they can be filtered out. "
        "_deprecated/ is excluded. Hunting queries are a separate source."
    ),
    "elastic_hunting": "hunting/ TOML queries from the detection-rules repo, counted as their own source.",
    "elastic_protections": "behavior/rules/ only (endpoint behaviour protections); other artifact types are not rules.",
    "splunk": "detections/ only; deprecated/ excluded. Stories, baselines and lookups are not counted.",
    "sublime": "detection-rules/ only; the repo's discovery-rules are not counted.",
    "lolrmm": "detections/sigma/ only -- the Sigma rendering of each RMM tool entry; the API/CSV renderings are not counted separately.",
    "sentinel": (
        "Solutions/*/Analytic Rules, root Detections/, ASIM/ and Summary rules "
        "are counted. Hunting Queries and Detection Queries exist in the "
        "checkout but are rejected at parse time -- hunting content is not a "
        "detection rule. Sparse checkout keeps the clone tractable."
    ),
    "google_secops": "rules/community/ only (YARA-L). rules/_deprecated/ is excluded and never checked out.",
    "okta": "detections/ only; hunts/, logs/, sample_osquery_checks/ and workflows/ are reference material, not rules.",
    "auth0": "detections/ only.",
    "panther": (
        "rules/ YAML+Python pairs on the develop branch, counted once per YAML. "
        "policies/, queries/, data_models/, packs/ and correlation_rules/ are not "
        "detection rules. deprecated.txt stamps status=deprecated on listed rules."
    ),
    "pypanther": "pypanther/rules/ Python rule classes on main; framework modules, tests and docs are not counted.",
}


@router.get("")
async def get_methodology(db: AsyncSession = Depends(get_db)):
    repos = {
        r.name: r
        for r in (await db.execute(select(Repository))).scalars().all()
    }
    sources = []
    for name in ALL_REPOSITORY_NAMES:
        config = RepositorySyncService.REPO_CONFIGS.get(name, {})
        patterns = RuleDiscoveryService.DISCOVERY_PATTERNS.get(name, {})
        repo = repos.get(name)
        sources.append({
            "name": name,
            "url": config.get("url"),
            "branch": SPARSE_CHECKOUT_BRANCHES.get(name, "master"),
            "sparse_checkout": SPARSE_CHECKOUT_PATTERNS.get(name),
            "include_patterns": list(patterns.get("include_patterns", [])),
            "exclude_dirs": sorted(patterns.get("exclude_dirs", [])),
            "scope_notes": SCOPE_NOTES.get(name, ""),
            "last_commit_hash": repo.last_commit_hash if repo else None,
            "last_sync_at": to_utc_iso(repo.last_sync_at) if repo else None,
            "rule_count": repo.rule_count if repo else None,
        })
    return {
        "generated_at": to_utc_iso(utcnow()),
        "principles": [
            "Every file our discovery globs match on the pinned commit is parsed; "
            "a count is reproducible from the commit hash alone.",
            "Deprecated content is excluded everywhere the vendor marks it; "
            "hunting content is not counted as detection rules.",
            "Building-block / signal-only rules are counted but flagged, so "
            "they can be excluded with one filter.",
            "After every sync the upstream tree is re-fetched via the GitHub API "
            "and our discovered count is checked against it (alerting past 5% drift).",
        ],
        "sources": sources,
    }
