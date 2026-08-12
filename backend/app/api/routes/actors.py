"""Threat Actors + Software (ATT&CK Groups + Software) API routes.

The full MITRE catalog (~180 groups + ~700 software) enumerated with
our corpus rule-coverage overlaid. For each detail request the client
picks a `match_mode` that decides which rules count as "this actor's":

- **exact**    rules tagged with the actor's raw ATT&CK ID via the
               `mitre_groups` / `mitre_software` JSON columns
               (populated during Sigma + LOLRMM ingestion). Strictest.
- **coverage** rules tagged with ANY of the techniques this actor
               is known to use (from MITRE STIX relationships).
               Reveals rules that would catch the actor's TTPs even
               without explicitly citing them.
- **mention**  rules whose title / description / tags contain the
               actor's name or one of its aliases as a whole word.
               Catches rules that reference the actor by name in
               prose but haven't been formally tagged.

The response carries counts for all three modes so the UI can render
a mode switcher without a round-trip. Rules for the SELECTED mode
are returned in the `rules` array.
"""

from __future__ import annotations

import re
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.actor_context import actor_context_service, merge_aliases
from app.services.actor_scores import actor_score_service
from app.services.mitre import mitre_service

router = APIRouter(prefix="/actors", tags=["actors"])


MatchMode = Literal["exact", "coverage", "mention"]
RULES_LIMIT = 200


# ── Helpers ────────────────────────────────────────────────────────

def _actor_type(actor_id: str) -> tuple[str, str]:
    """Return (kind, mitre_url) for an actor ID. Raises 400 on unknown shape."""
    if actor_id.startswith("G"):
        return "group", f"https://attack.mitre.org/groups/{actor_id}/"
    if actor_id.startswith("S"):
        return "software", f"https://attack.mitre.org/software/{actor_id}/"
    raise HTTPException(
        status_code=400,
        detail=f"Invalid actor id: {actor_id}. Expected G#### or S####.",
    )


async def _rules_matching_ids(
    db: AsyncSession, column, ids: list[str],
) -> list[Detection]:
    """Rules where the JSON list column contains ANY of `ids`."""
    if not ids:
        return []
    conds = [cast(column, String).ilike(f'%"{i}"%') for i in ids]
    q = (
        select(
            Detection.id, Detection.rule_id, Detection.title, Detection.source,
            Detection.severity, Detection.language, Detection.mitre_techniques,
            Detection.platforms, Detection.rule_created_date,
        )
        .where(or_(*conds))
        .limit(RULES_LIMIT)
    )
    return list((await db.execute(q)).all())


async def _rules_mentioning(
    db: AsyncSession, names: list[str],
) -> list[Detection]:
    """Rules whose title/description/tags mention any of `names` as a whole word.

    Two-stage: DB-side ilike substring pre-filter (portable) narrows
    the set, then a Python word-boundary regex removes false-matches
    like `apt29ish` or `notmimikatz`.
    """
    if not names:
        return []
    # Ignore very short names (< 3 chars) as substrings — too many
    # false hits. Real ATT&CK names are always longer.
    filtered = [n for n in names if len(n) >= 3]
    if not filtered:
        return []
    ilike_conds = []
    for n in filtered:
        pattern = f"%{n}%"
        ilike_conds.extend([
            Detection.title.ilike(pattern),
            Detection.description.ilike(pattern),
            cast(Detection.tags, String).ilike(pattern),
        ])
    q = (
        select(
            Detection.id, Detection.rule_id, Detection.title, Detection.source,
            Detection.severity, Detection.language, Detection.mitre_techniques,
            Detection.platforms, Detection.rule_created_date,
            Detection.description, Detection.tags,
        )
        .where(or_(*ilike_conds))
        .limit(RULES_LIMIT * 3)  # over-fetch; Python regex filters below
    )
    raw = list((await db.execute(q)).all())

    # Word-boundary regex, case-insensitive. Escape names for regex.
    pattern = re.compile(
        r"\b(" + "|".join(re.escape(n) for n in filtered) + r")\b",
        re.IGNORECASE,
    )
    hits = []
    for row in raw:
        title = row[2] or ""
        description = row[9] or ""
        tags = " ".join(t for t in (row[10] or []) if isinstance(t, str))
        if pattern.search(title) or pattern.search(description) or pattern.search(tags):
            hits.append(row)
        if len(hits) >= RULES_LIMIT:
            break
    return hits


def _serialize_rule(row) -> dict:
    """Turn a Detection row tuple into the wire shape."""
    return {
        "id": row[0],
        "rule_id": row[1],
        "title": row[2],
        "source": row[3],
        "severity": row[4],
        "language": row[5],
        "techniques": row[6] or [],
        "platforms": row[7] or [],
        "date": row[8].isoformat() if row[8] else None,
    }


async def _count_matches(db: AsyncSession, column, ids: list[str]) -> int:
    """Count of rules matching any of `ids` in the JSON list column.

    Kept as a separate query so we can return counts for all three
    modes on the detail response without over-fetching rules for the
    non-selected modes.
    """
    if not ids:
        return 0
    from sqlalchemy import func
    conds = [cast(column, String).ilike(f'%"{i}"%') for i in ids]
    q = select(func.count(Detection.id)).where(or_(*conds))
    return (await db.execute(q)).scalar() or 0


# ── Endpoints ─────────────────────────────────────────────────────

@router.get("")
async def list_actors(
    db: AsyncSession = Depends(get_db),
):
    """Enumerate the full MITRE catalog with corpus rule-coverage overlaid.

    Returns two lists:
      - `groups`:   every G-ID from MITRE, sorted by weighted_gap desc
                    (most outstanding detection work first).
      - `software`: same shape for S-IDs.

    Each entry: id, name, aliases (groups) / type (software),
    description snippet (truncated), our_rule_count (exact match),
    technique_count (from MITRE), covered_technique_count (raw), plus
    the distinctiveness-weighted scores: weighted_coverage (0..1 or
    null), gap_count, weighted_gap. Scores are materialized by the
    actor-score service — no per-request corpus scan.
    """
    await mitre_service.ensure_loaded()
    await actor_context_service.ensure_loaded()
    catalog_groups = mitre_service.get_all_groups()
    catalog_software = mitre_service.get_all_software()
    bundle = await actor_score_service.get(db)

    def _short(desc: str, n: int = 240) -> str:
        d = (desc or "").strip()
        return d if len(d) <= n else d[: n - 1].rstrip() + "…"

    def _scores(sc) -> dict:
        return {
            "technique_count": sc.technique_count,
            "covered_technique_count": sc.covered_technique_count,
            "our_rule_count": sc.exact_rule_count,
            "sources_with_coverage": sc.sources,
            "weighted_coverage": (
                round(sc.weighted_coverage, 4)
                if sc.weighted_coverage is not None else None
            ),
            "gap_count": sc.gap_count,
            "weighted_gap": round(sc.weighted_gap, 4),
        }

    def _group_entry(g: dict) -> dict:
        sc = bundle.groups[g["id"]]
        ctx = actor_context_service.get_context(g["id"]) or {}
        return {
            "id": g["id"],
            "name": g["name"],
            "aliases": merge_aliases(g["aliases"], ctx, exclude=g["name"]),
            "description": _short(g["description"]),
            "deprecated": g.get("deprecated", False),
            # MISP-galaxy context — nullable/empty when no match.
            "origin_country": ctx.get("origin_country"),
            "motivations": ctx.get("motivations", []),
            "target_sectors": ctx.get("target_sectors", []),
            "target_regions": ctx.get("target_regions", []),
            **_scores(sc),
        }

    def _software_entry(s: dict) -> dict:
        sc = bundle.software[s["id"]]
        return {
            "id": s["id"],
            "name": s["name"],
            "type": s["type"],
            "aliases": s.get("aliases", []),
            "description": _short(s["description"]),
            "deprecated": s.get("deprecated", False),
            "platforms": s.get("platforms", []),
            **_scores(sc),
        }

    groups = [_group_entry(g) for g in catalog_groups.values()]
    software = [_software_entry(s) for s in catalog_software.values()]

    # Rank by outstanding weighted detection work, most first. Ties
    # (e.g. zero-gap actors) break toward more exact rules, then ID.
    def _key(e: dict) -> tuple:
        return (-e["weighted_gap"], -e["our_rule_count"], e["id"])

    groups.sort(key=_key)
    software.sort(key=_key)

    return {
        "groups": groups,
        "software": software,
        "total_groups": len(groups),
        "total_software": len(software),
        # Count of entries we have ANY rule coverage for. Useful signal.
        "groups_with_coverage": sum(1 for g in groups if g["our_rule_count"] > 0),
        "software_with_coverage": sum(1 for s in software if s["our_rule_count"] > 0),
    }


@router.get("/{actor_id}")
async def get_actor(
    actor_id: str,
    match_mode: MatchMode = Query(
        "exact",
        description=(
            "How to find rules for this actor. `exact` = tagged with the "
            "raw ATT&CK ID. `coverage` = tagged with any technique the "
            "actor is known to use. `mention` = actor name or alias "
            "appears as a whole word in title/description/tags."
        ),
    ),
    db: AsyncSession = Depends(get_db),
):
    """Actor / software detail overlaying MITRE metadata + rule coverage.

    Returns MITRE-parity metadata (description, aliases, references,
    techniques used, cross-referenced software/groups) plus:

    - `techniques`: full MITRE list annotated with `has_rules` +
      `rule_count` from our corpus so the UI can show gaps at a glance.
    - `associated_software` (groups) / `associated_groups` (software):
      cross-referenced entries with their own `has_rules` flag.
    - `match_counts`: rule count for each of the three match modes,
      always populated so the UI can render a mode switcher.
    - `rules`: rules array matching the SELECTED `match_mode`, capped
      at 200. Sorted by (source, title).
    """
    actor_id = actor_id.upper()
    kind, mitre_url = _actor_type(actor_id)

    await mitre_service.ensure_loaded()
    await actor_context_service.ensure_loaded()
    if kind == "group":
        entity = mitre_service.get_group(actor_id)
    else:
        entity = mitre_service.get_software(actor_id)

    if entity is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown actor id: {actor_id}",
        )

    bundle = await actor_score_service.get(db)
    scores = (bundle.groups if kind == "group" else bundle.software)[actor_id]

    # Techniques used by this actor, annotated with our coverage and
    # the distinctiveness weight driving the weighted scores.
    techniques_used = []
    for tid in entity.get("techniques", []):
        tid_u = tid.upper()
        rule_count = bundle.technique_rule_counts.get(tid_u, 0)
        tech_info = mitre_service.get_technique(tid_u)
        weight = tech_info.get("actor_weight") if tech_info else None
        techniques_used.append({
            "technique_id": tid_u,
            "technique_name": tech_info.get("name", "") if tech_info else "",
            "has_rules": rule_count > 0,
            "rule_count": rule_count,
            "weight": round(weight, 4) if weight is not None else None,
        })
    # Sort: covered first (rule_count desc), then uncovered alphabetically.
    techniques_used.sort(key=lambda t: (-t["rule_count"], t["technique_id"]))
    covered_count = sum(1 for t in techniques_used if t["has_rules"])

    # Cross-references
    if kind == "group":
        associated = []
        for sid in entity.get("software", []):
            s = mitre_service.get_software(sid)
            if not s:
                continue
            sw_sc = bundle.software.get(sid)
            sw_rules = sw_sc.exact_rule_count if sw_sc else 0
            associated.append({
                "id": sid,
                "name": s["name"],
                "type": s["type"],
                "has_rules": sw_rules > 0,
                "rule_count": sw_rules,
            })
        associated_key = "associated_software"
    else:
        associated = []
        for gid in entity.get("groups", []):
            g = mitre_service.get_group(gid)
            if not g:
                continue
            gr_sc = bundle.groups.get(gid)
            gr_rules = gr_sc.exact_rule_count if gr_sc else 0
            associated.append({
                "id": gid,
                "name": g["name"],
                "aliases": g.get("aliases", []),
                "has_rules": gr_rules > 0,
                "rule_count": gr_rules,
            })
        associated_key = "associated_groups"
    associated.sort(key=lambda a: (-a["rule_count"], a["id"]))

    # Match counts across all three modes — always populated so the
    # UI can render the switcher without a round-trip.
    column = Detection.mitre_groups if kind == "group" else Detection.mitre_software
    exact_count = await _count_matches(db, column, [actor_id])
    coverage_ids = [t["technique_id"] for t in techniques_used]
    coverage_count = await _count_matches(db, Detection.mitre_techniques, coverage_ids)

    # Mention count: names to search for = primary name + aliases,
    # including galaxy synonyms (a rule citing "GOLD SAHARA" counts
    # as mentioning Akira).
    mention_ctx = (
        actor_context_service.get_context(actor_id) if kind == "group" else None
    )
    mention_names = [entity["name"]] + merge_aliases(
        list(entity.get("aliases", [])), mention_ctx, exclude=entity["name"]
    )
    mention_hits = await _rules_mentioning(db, mention_names)
    mention_count = len(mention_hits)

    # Fetch rules for the SELECTED mode
    if match_mode == "exact":
        rule_rows = await _rules_matching_ids(db, column, [actor_id])
    elif match_mode == "coverage":
        rule_rows = await _rules_matching_ids(db, Detection.mitre_techniques, coverage_ids)
    else:  # mention
        rule_rows = mention_hits

    rules = [_serialize_rule(r) for r in rule_rows]
    rules.sort(key=lambda r: (r["source"], r["title"]))

    # Galaxy context (groups only) — merged aliases + appended refs.
    ctx = actor_context_service.get_context(actor_id) if kind == "group" else None
    references = list(entity.get("references", []))
    if ctx:
        known_urls = {r.get("url") for r in references}
        for url in ctx.get("references", []):
            if url in known_urls:
                continue
            known_urls.add(url)
            domain = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
            references.append(
                {"source_name": domain, "url": url, "description": ""}
            )

    # Build the response
    metadata: dict = {
        "id": actor_id,
        "kind": kind,
        "name": entity["name"],
        "description": entity["description"],
        "mitre_url": mitre_url,
        "references": references,
        "deprecated": entity.get("deprecated", False),
        "aliases": merge_aliases(
            entity.get("aliases", []), ctx, exclude=entity["name"]
        ),
        # MISP-galaxy context — null/empty when no galaxy match (about
        # a third of actors); the UI omits rather than placeholders.
        "origin_country": (ctx or {}).get("origin_country"),
        "motivations": (ctx or {}).get("motivations", []),
        "target_sectors": (ctx or {}).get("target_sectors", []),
        "target_regions": (ctx or {}).get("target_regions", []),
        "target_countries": (ctx or {}).get("target_countries", []),
    }
    if kind == "software":
        metadata["type"] = entity["type"]
        metadata["platforms"] = entity.get("platforms", [])

    return {
        **metadata,
        # Raw coverage — retained for the detail page ("did we look at
        # every technique"), no longer the ranking metric.
        "technique_count": len(techniques_used),
        "covered_technique_count": covered_count,
        # Distinctiveness-weighted scores (see actor_scores service).
        "weighted_coverage": (
            round(scores.weighted_coverage, 4)
            if scores.weighted_coverage is not None else None
        ),
        "gap_count": scores.gap_count,
        "weighted_gap": round(scores.weighted_gap, 4),
        "techniques": techniques_used,
        associated_key: associated,
        "match_counts": {
            "exact": exact_count,
            "coverage": coverage_count,
            "mention": mention_count,
        },
        "match_mode": match_mode,
        "rules": rules,
    }
