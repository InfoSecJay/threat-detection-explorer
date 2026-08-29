"""Threat Actors + Software (ATT&CK Groups + Software) API routes.

The full MITRE catalog (~180 groups + ~700 software) enumerated with
our corpus rule-coverage overlaid. For each detail request the client
picks a `match_mode` that decides which rules count as "this actor's":

The three modes are DISJOINT tiers of attribution strength (issue #34).
Wire values keep their historical names (`exact` / `coverage` /
`mention`) so URLs and deployed frontends never skew; the UI renders
them as DEDICATED / COVERAGE / REFERENCED.

- **exact** ("Dedicated") — the rule was built FOR this actor:
  tagged with the raw ATT&CK ID (`mitre_groups` / `mitre_software`),
  OR a `use_cases` label (vendor analytic story) equal to the actor's
  name or an alias, OR the actor's name/alias in the rule TITLE.
  A rule titled "APT29 2018 Phishing Campaign ..." is an APT29 rule.
- **coverage** — rules tagged with ANY of the techniques this actor
  is known to use (from MITRE STIX relationships). Reveals rules that
  would catch the actor's TTPs even without citing them.
- **mention** ("Referenced") — the name or an alias appears only in
  description prose, non-story tags, longer use_cases labels, or
  reference URLs — MINUS everything Dedicated. Separator-tolerant
  matching throughout (see app.services.actor_matching).

Every rule returned in exact/mention mode carries `match_reasons`
(subset of: id-tag, story, title, description, tag, use-case,
reference) so the UI can show WHY each rule counted.

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
from app.services.actor_matching import (
    compile_name_regex,
    is_case_sensitive_name,
    label_like_patterns,
    labels_matching,
    sql_like_patterns,
)
from app.services.actor_scores import actor_score_service
from app.services.mitre import mitre_service
from app.utils.datetime_utils import to_utc_iso, utcnow

router = APIRouter(prefix="/actors", tags=["actors"])

# Alias router so the documented /api/software/{S-ID}/navigator-layer
# path works; software detail itself lives under /actors/{S-ID}.
software_router = APIRouter(prefix="/software", tags=["actors"])


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


# Fetch window for dedicated candidates. Above RULES_LIMIT because
# len() of the verified set IS the exact-mode count shown in the UI —
# a display cap must not silently truncate the count. No actor comes
# near this today (Salt Typhoon, the largest, has 60).
DEDICATED_FETCH_CAP = 2000

# The nine columns every rule-row tuple starts with; extra columns
# needed for verification are appended after these.
_RULE_COLS = (
    Detection.id, Detection.rule_id, Detection.title, Detection.source,
    Detection.severity, Detection.language, Detection.mitre_techniques,
    Detection.platforms, Detection.rule_created_date,
)


def _name_text_conds(column, names: list[str]) -> list:
    """LIKE pre-filter conditions for `names` over one text column,
    honoring the case-sensitivity policy (LEAD matches only LEAD)."""
    conds = []
    for n in names:
        if is_case_sensitive_name(n):
            conds.append(column.like(f"%{n}%"))
            continue
        conds.extend(column.ilike(p) for p in sql_like_patterns(n))
    return conds


async def _rules_matching_ids(
    db: AsyncSession, column, ids: list[str],
) -> list[Detection]:
    """Rules where the JSON list column contains ANY of `ids` —
    coverage mode."""
    if not ids:
        return []
    conds = [cast(column, String).ilike(f'%"{i}"%') for i in ids]
    q = select(*_RULE_COLS).where(or_(*conds)).limit(RULES_LIMIT)
    return list((await db.execute(q)).all())


async def _dedicated_rules(
    db: AsyncSession, column, actor_id: str, names: list[str],
) -> tuple[list, dict[str, list[str]]]:
    """Rules BUILT FOR this actor, with the reason(s) each qualified.

    Three signals, any of which qualifies a rule (issue #34):
    - `id-tag`  the raw ATT&CK ID in the mitre_groups/software column
    - `story`   a use_cases label EQUAL to the name/an alias
    - `title`   the name/an alias in the rule title

    SQL is a pre-filter; each candidate is verified in Python so the
    LIKE over-match ("%lead%") never inflates the count. Returns
    (rows, {rule_id: [reasons]}).
    """
    filtered = [n for n in names if len(n) >= 3]
    conds = [cast(column, String).ilike(f'%"{actor_id}"%')]
    for n in filtered:
        conds.extend(
            cast(Detection.use_cases, String).ilike(p)
            for p in label_like_patterns(n)
        )
    conds.extend(_name_text_conds(Detection.title, filtered))
    q = (
        select(*_RULE_COLS, Detection.use_cases, cast(column, String))
        .where(or_(*conds))
        .limit(DEDICATED_FETCH_CAP)
    )
    raw = list((await db.execute(q)).all())

    title_rx = compile_name_regex(filtered)
    rows, reasons = [], {}
    for row in raw:
        why = []
        if f'"{actor_id}"'.lower() in (row[10] or "").lower():
            why.append("id-tag")
        if labels_matching(row[9] or [], filtered):
            why.append("story")
        if title_rx and title_rx.search(row[2] or ""):
            why.append("title")
        if why:
            rows.append(row)
            reasons[row[0]] = why
    return rows, reasons


async def _referenced_rules(
    db: AsyncSession, names: list[str], dedicated_ids: set[str],
) -> tuple[list, dict[str, list[str]]]:
    """Mention hits MINUS dedicated rules, with per-rule reasons
    (description / tag / use-case / reference)."""
    hits = await _rules_mentioning(db, names)
    filtered = [n for n in names if len(n) >= 3]
    rx = compile_name_regex(filtered)
    rows, reasons = [], {}
    for row in hits:
        if row[0] in dedicated_ids or rx is None:
            continue
        why = []
        if rx.search(row[9] or ""):
            why.append("description")
        if rx.search(" ".join(t for t in (row[10] or []) if isinstance(t, str))):
            why.append("tag")
        if rx.search(" ".join(u for u in (row[11] or []) if isinstance(u, str))):
            why.append("use-case")
        if rx.search(" ".join(r for r in (row[12] or []) if isinstance(r, str))):
            why.append("reference")
        if why:
            rows.append(row)
            reasons[row[0]] = why
    return rows, reasons


async def _rules_mentioning(
    db: AsyncSession, names: list[str],
) -> list[Detection]:
    """Rules whose title/description/tags/use_cases/references mention
    any of `names`, separator-tolerant.

    Two-stage: DB-side LIKE pre-filter (portable; `_` wildcard covers
    space/underscore/hyphen variants) narrows the set, then the shared
    actor_matching regex — alphanumeric-boundary lookarounds, flexible
    separators — removes false matches like `apt29ish` while still
    hitting `story:salt_typhoon` and `.../salt-typhoon-analysis/`.
    """
    if not names:
        return []
    # Ignore very short names (< 3 chars) as substrings — too many
    # false hits. Real ATT&CK names are always longer.
    filtered = [n for n in names if len(n) >= 3]
    if not filtered:
        return []
    text_columns = (
        Detection.title,
        Detection.description,
        cast(Detection.tags, String),
        cast(Detection.use_cases, String),
        cast(Detection.references, String),
    )
    ilike_conds = []
    for n in filtered:
        if is_case_sensitive_name(n):
            # Exact-case codename (LEAD, BARIUM): case-sensitive LIKE
            # on Postgres so prose hits ("may lead to") don't consume
            # the over-fetch window. SQLite's LIKE stays
            # case-insensitive — a looser pre-filter there is fine,
            # the regex below is the authority.
            ilike_conds.extend(col.like(f"%{n}%") for col in text_columns)
            continue
        for pattern in sql_like_patterns(n):
            ilike_conds.extend(col.ilike(pattern) for col in text_columns)
    q = (
        select(
            Detection.id, Detection.rule_id, Detection.title, Detection.source,
            Detection.severity, Detection.language, Detection.mitre_techniques,
            Detection.platforms, Detection.rule_created_date,
            Detection.description, Detection.tags,
            Detection.use_cases, Detection.references,
        )
        .where(or_(*ilike_conds))
        .limit(RULES_LIMIT * 3)  # over-fetch; Python regex filters below
    )
    raw = list((await db.execute(q)).all())

    pattern = compile_name_regex(filtered)
    if pattern is None:
        return []
    hits = []
    for row in raw:
        haystack = " ".join([
            row[2] or "",   # title
            row[9] or "",   # description
            " ".join(t for t in (row[10] or []) if isinstance(t, str)),  # tags
            " ".join(u for u in (row[11] or []) if isinstance(u, str)),  # use_cases
            " ".join(r for r in (row[12] or []) if isinstance(r, str)),  # references
        ])
        if pattern.search(haystack):
            hits.append(row)
        if len(hits) >= RULES_LIMIT:
            break
    return hits


def _serialize_rule(row, reasons: dict[str, list[str]] | None = None) -> dict:
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
        "date": to_utc_iso(row[8]),
        # Why this rule counted under the selected mode (issue #34).
        # Empty for coverage mode — the technique tag is the reason.
        "match_reasons": (reasons or {}).get(row[0], []),
    }


async def _count_matches(db: AsyncSession, column, ids: list[str]) -> int:
    """Count of rules matching any of `ids` in the JSON list column
    (coverage mode). Dedicated/referenced counts come from their
    verified row sets instead — SQL alone can't apply the regex."""
    if not ids:
        return 0
    from sqlalchemy import func
    conds = [cast(column, String).ilike(f'%"{i}"%') for i in ids]
    q = select(func.count(Detection.id)).where(or_(*conds))
    return (await db.execute(q)).scalar() or 0


# ── List building ─────────────────────────────────────────────────

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
        "mention_count": sc.mention_count,
    }


def _group_entry(g: dict, bundle) -> dict:
    sc = bundle.groups[g["id"]]
    ctx = actor_context_service.get_context(g["id"]) or {}
    return {
        "id": g["id"],
        "name": g["name"],
        "aliases": merge_aliases(g["aliases"], ctx, exclude=g["name"]),
        "description": _short(g["description"]),
        "deprecated": g.get("deprecated", False),
        "modified": g.get("modified"),
        # MISP-galaxy context — nullable/empty when no match.
        "origin_country": ctx.get("origin_country"),
        "motivations": ctx.get("motivations", []),
        "target_sectors": ctx.get("target_sectors", []),
        "target_regions": ctx.get("target_regions", []),
        **_scores(sc),
    }


def _software_entry(s: dict, bundle) -> dict:
    sc = bundle.software[s["id"]]
    used_by = s.get("groups", [])
    return {
        "id": s["id"],
        "name": s["name"],
        "type": s["type"],
        "aliases": s.get("aliases", []),
        "description": _short(s["description"]),
        "deprecated": s.get("deprecated", False),
        "modified": s.get("modified"),
        "platforms": s.get("platforms", []),
        # A rule covering software many actors share is the
        # highest-leverage detection on the site — this is the
        # software tab's primary stat and default sort.
        "used_by_actor_count": len(used_by),
        "used_by_actors": used_by,
        **_scores(sc),
    }


def _rank_key(e: dict) -> tuple:
    """Default rank: outstanding weighted detection work, most first.
    Ties (e.g. zero-gap actors) break toward more exact rules, then ID."""
    return (-e["weighted_gap"], -e["our_rule_count"], e["id"])


# ── Filtering / faceting (Phase 4) ────────────────────────────────

# Filterable dimensions -> entry key holding the value(s), per kind.
GROUP_FACET_DIMS = {
    "sector": "target_sectors",
    "region": "target_regions",
    "motivation": "motivations",
    "origin": "origin_country",
}
SOFTWARE_FACET_DIMS = {
    "type": "type",
}

SORT_KEYS = {
    "name": lambda e: (e["name"] or "").lower(),
    "origin": lambda e: (e.get("origin_country") or "￿"),
    "motivation": lambda e: (e.get("motivations") or ["￿"])[0],
    "technique_count": lambda e: e["technique_count"],
    "gap_count": lambda e: e["gap_count"],
    "weighted_gap": lambda e: e["weighted_gap"],
    "weighted_coverage": lambda e: (
        e["weighted_coverage"] if e["weighted_coverage"] is not None else -1
    ),
    "our_rule_count": lambda e: e["our_rule_count"],
    "mention_count": lambda e: e.get("mention_count", 0),
    "modified": lambda e: e.get("modified") or "",
    # Software-only keys (0 / '' on groups, harmless).
    "used_by_actor_count": lambda e: e.get("used_by_actor_count", 0),
    "type": lambda e: e.get("type") or "",
}


def _entry_values(entry: dict, key: str) -> list[str]:
    v = entry.get(key)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _apply_filters(
    entries: list[dict],
    dims_map: dict[str, str],
    dims: dict[str, Optional[list[str]]],
    min_gaps: Optional[int],
    has_exact_rules: Optional[bool],
    q: Optional[str],
    used_by_actor: Optional[str] = None,
) -> list[dict]:
    """Multi-select within a dimension is OR; across dimensions AND."""
    out = []
    ql = (q or "").strip().lower()
    uba = (used_by_actor or "").strip().upper()
    for e in entries:
        ok = True
        for dim, wanted in dims.items():
            if not wanted or dim not in dims_map:
                continue
            values = set(_entry_values(e, dims_map[dim]))
            if not values.intersection(wanted):
                ok = False
                break
        if not ok:
            continue
        if min_gaps is not None and e["gap_count"] < min_gaps:
            continue
        if has_exact_rules is not None and (e["our_rule_count"] > 0) != has_exact_rules:
            continue
        if uba and uba not in e.get("used_by_actors", []):
            continue
        if ql:
            hay = " ".join([e["name"], e["id"], *e.get("aliases", [])]).lower()
            if ql not in hay:
                continue
        out.append(e)
    return out


def _facets(
    entries: list[dict],
    dims_map: dict[str, str],
    dims: dict[str, Optional[list[str]]],
    min_gaps: Optional[int],
    has_exact_rules: Optional[bool],
    q: Optional[str],
    used_by_actor: Optional[str] = None,
) -> dict[str, dict[str, int]]:
    """Counts per dimension value, with every OTHER filter applied —
    the count a chip would produce if the user clicked it next."""
    facets: dict[str, dict[str, int]] = {}
    for dim in dims_map:
        others = {d: (None if d == dim else w) for d, w in dims.items()}
        pool = _apply_filters(
            entries, dims_map, others, min_gaps, has_exact_rules, q, used_by_actor
        )
        counts: dict[str, int] = {}
        for e in pool:
            for v in _entry_values(e, dims_map[dim]):
                counts[v] = counts.get(v, 0) + 1
        facets[dim] = dict(
            sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )
    return facets


# ── Endpoints ─────────────────────────────────────────────────────

@router.get("")
async def list_actors(
    kind: Optional[Literal["groups", "software"]] = Query(
        None, description="Object class to query (filtered mode)."
    ),
    sector: Optional[list[str]] = Query(None),
    region: Optional[list[str]] = Query(None),
    motivation: Optional[list[str]] = Query(None),
    origin: Optional[list[str]] = Query(None),
    type: Optional[list[str]] = Query(
        None, description="Software only: tool (dual-use) | malware (bespoke)."
    ),
    used_by_actor: Optional[str] = Query(
        None, description="Software only: G-ID; show software this actor uses."
    ),
    min_gaps: Optional[int] = Query(None, ge=0),
    has_exact_rules: Optional[bool] = Query(None),
    q: Optional[str] = Query(None, description="Free text over name + aliases + ID"),
    sort: Optional[str] = Query(None, description=f"One of {sorted(SORT_KEYS)}"),
    order: Literal["asc", "desc"] = Query("desc"),
    page: Optional[int] = Query(None, ge=1),
    per_page: Optional[int] = Query(None, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Enumerate the MITRE catalog with corpus rule-coverage overlaid.

    Two response shapes:

    - **No query params** (legacy, public API): `{groups, software,
      total_groups, total_software, groups_with_coverage,
      software_with_coverage}` — the full catalog, both classes,
      ranked by weighted_gap desc.
    - **Any param present** (filtered): `{items, total, page,
      per_page, facets, summary}` for the requested `kind` (default
      groups). Multi-select filters OR within a dimension, AND across
      dimensions; `facets` carries value counts with every other
      filter applied so chips can show result counts up front.

    Everything is served from the precomputed score bundle — no
    per-request corpus scan.
    """
    await mitre_service.ensure_loaded()
    await actor_context_service.ensure_loaded()
    catalog_groups = mitre_service.get_all_groups()
    catalog_software = mitre_service.get_all_software()
    bundle = await actor_score_service.get(db)

    groups = [_group_entry(g, bundle) for g in catalog_groups.values()]
    software = [_software_entry(s, bundle) for s in catalog_software.values()]
    groups.sort(key=_rank_key)
    software.sort(key=_rank_key)

    filtered_mode = any(
        p is not None
        for p in (kind, sector, region, motivation, origin, type, used_by_actor,
                  min_gaps, has_exact_rules, q, sort, page, per_page)
    )

    if not filtered_mode:
        return {
            "groups": groups,
            "software": software,
            "total_groups": len(groups),
            "total_software": len(software),
            # Count of entries we have ANY rule coverage for.
            "groups_with_coverage": sum(1 for g in groups if g["our_rule_count"] > 0),
            "software_with_coverage": sum(1 for s in software if s["our_rule_count"] > 0),
        }

    if sort is not None and sort not in SORT_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort key: {sort}. Expected one of {sorted(SORT_KEYS)}.",
        )

    is_software = kind == "software"
    entries = software if is_software else groups
    dims_map = SOFTWARE_FACET_DIMS if is_software else GROUP_FACET_DIMS
    dims = (
        {"type": type}
        if is_software
        else {
            "sector": sector, "region": region,
            "motivation": motivation, "origin": origin,
        }
    )
    hits = _apply_filters(
        entries, dims_map, dims, min_gaps, has_exact_rules, q,
        used_by_actor if is_software else None,
    )

    if sort is not None:
        hits.sort(key=SORT_KEYS[sort], reverse=(order == "desc"))
    elif is_software:
        # Software default: most-shared tooling first — a rule for
        # software used by dozens of actors is the highest-leverage
        # detection on the site.
        hits.sort(
            key=lambda e: (e["used_by_actor_count"], e["weighted_gap"]),
            reverse=(order == "desc"),
        )
    elif order == "asc":
        hits.reverse()  # default rank is weighted_gap desc

    page_n = page or 1
    size = per_page or 50
    start = (page_n - 1) * size

    return {
        "items": hits[start:start + size],
        "total": len(hits),
        "page": page_n,
        "per_page": size,
        "facets": _facets(
            entries, dims_map, dims, min_gaps, has_exact_rules, q,
            used_by_actor if is_software else None,
        ),
        "summary": {
            "total_groups": len(groups),
            "total_software": len(software),
            "groups_with_coverage": sum(1 for g in groups if g["our_rule_count"] > 0),
            "software_with_coverage": sum(1 for s in software if s["our_rule_count"] > 0),
        },
    }


# ── ATT&CK Navigator layer export (Phase 6) ───────────────────────

NAVIGATOR_VERSION = "5.1.0"
LAYER_FORMAT = "4.5"
COMMENT_TITLE_CAP = 10
# Rules scanned for per-technique comments; far above the corpus size,
# just a runaway guard.
LAYER_RULES_CAP = 50000

# Red -> amber -> green. Score 0 (gap) renders red — the zeros are
# the point of the export.
LAYER_GRADIENT = ["#b71c1c", "#f9a825", "#2e7d32"]


async def _technique_rule_titles(
    db: AsyncSession, technique_ids: list[str], restrict_rows=None,
) -> dict[str, list[str]]:
    """technique id -> titles of rules tagging it. `restrict_rows`
    (rows with .title / .mitre_techniques-like tuple) limits the pool
    for exact/mention modes; otherwise the corpus is queried."""
    titles: dict[str, list[str]] = {t: [] for t in technique_ids}
    wanted = set(technique_ids)
    if restrict_rows is not None:
        pool = [(r[2], r[6] or []) for r in restrict_rows]  # title, techniques
    else:
        conds = [
            cast(Detection.mitre_techniques, String).ilike(f'%"{t}"%')
            for t in technique_ids
        ]
        if not conds:
            return titles
        q = (
            select(Detection.title, Detection.mitre_techniques)
            .where(or_(*conds))
            .limit(LAYER_RULES_CAP)
        )
        pool = [(row[0], row[1] or []) for row in (await db.execute(q)).all()]
    for title, techs in pool:
        for t in techs:
            t_u = t.upper()
            if t_u in wanted:
                titles[t_u].append(title)
    return titles


def _technique_comment(titles: list[str]) -> str:
    if not titles:
        return ""
    shown = titles[:COMMENT_TITLE_CAP]
    overflow = len(titles) - len(shown)
    comment = " | ".join(shown)
    if overflow > 0:
        comment += f" | (+{overflow} more)"
    return comment


def _build_layer(
    *,
    name: str,
    description: str,
    technique_scores: dict[str, int],
    technique_comments: dict[str, str],
    metadata: list[dict],
) -> dict:
    max_score = max(technique_scores.values(), default=0)
    techniques = [
        {
            "techniqueID": tid,
            "score": score,
            "comment": technique_comments.get(tid, ""),
            "enabled": True,  # zeros stay enabled — they ARE the point
            "showSubtechniques": False,
        }
        for tid, score in sorted(technique_scores.items())
    ]
    return {
        "name": name,
        "versions": {
            "attack": mitre_service.get_attack_version() or "unknown",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT,
        },
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": LAYER_GRADIENT,
            "minValue": 0,
            "maxValue": max(max_score, 1),
        },
        "legendItems": [
            {"color": LAYER_GRADIENT[0], "label": "0 rules — detection gap"},
            {"color": LAYER_GRADIENT[1], "label": "partial rule coverage"},
            {"color": LAYER_GRADIENT[2], "label": f"{max(max_score, 1)} rules (max observed)"},
        ],
        "metadata": metadata,
        "sorting": 0,
    }


def _layer_response(layer: dict, filename: str):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/navigator-layer")
async def bulk_navigator_layer(
    sector: Optional[list[str]] = Query(None),
    region: Optional[list[str]] = Query(None),
    motivation: Optional[list[str]] = Query(None),
    origin: Optional[list[str]] = Query(None),
    min_gaps: Optional[int] = Query(None, ge=0),
    has_exact_rules: Optional[bool] = Query(None),
    q: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Combined Navigator layer for the current actor filter set —
    "everything targeting telecom, scored by our coverage" as one
    downloadable deliverable. Scores are corpus rule counts per
    technique (coverage semantics); comments say how many of the
    filtered actors use each technique.
    """
    await mitre_service.ensure_loaded()
    await actor_context_service.ensure_loaded()
    bundle = await actor_score_service.get(db)

    groups = [_group_entry(g, bundle) for g in mitre_service.get_all_groups().values()]
    dims = {
        "sector": sector, "region": region,
        "motivation": motivation, "origin": origin,
    }
    hits = _apply_filters(groups, GROUP_FACET_DIMS, dims, min_gaps, has_exact_rules, q)
    if not hits:
        raise HTTPException(status_code=404, detail="No actors match this filter set.")

    catalog = mitre_service.get_all_groups()
    usage: dict[str, int] = {}
    for e in hits:
        for tid in catalog[e["id"]].get("techniques", []):
            usage[tid.upper()] = usage.get(tid.upper(), 0) + 1

    technique_scores = {
        tid: bundle.technique_rule_counts.get(tid, 0) for tid in usage
    }
    technique_titles = await _technique_rule_titles(db, list(usage))
    # Actor-usage context first, then matching rule titles.
    technique_comments = {}
    for tid in usage:
        prefix = f"used by {usage[tid]}/{len(hits)} filtered actors"
        rules = _technique_comment(technique_titles.get(tid, []))
        technique_comments[tid] = f"{prefix} | {rules}" if rules else prefix

    filters_desc = ", ".join(
        f"{k}={'|'.join(v)}" for k, v in dims.items() if v
    ) or "no filters"
    if min_gaps is not None:
        filters_desc += f", min_gaps={min_gaps}"
    if has_exact_rules is not None:
        filters_desc += f", has_exact_rules={has_exact_rules}"
    if q:
        filters_desc += f", q={q}"

    layer = _build_layer(
        name=f"Detection coverage — {len(hits)} actors ({filters_desc})",
        description=(
            f"Union of techniques used by {len(hits)} ATT&CK groups matching "
            f"[{filters_desc}], scored by detection-rule count in the "
            "Detection Explorer corpus (coverage match mode)."
        ),
        technique_scores=technique_scores,
        technique_comments=technique_comments,
        metadata=[
            {"name": "source", "value": "detectionexplorer.io"},
            {"name": "actors", "value": ", ".join(e["id"] for e in hits[:50])},
            {"name": "filter", "value": filters_desc},
            {"name": "generated", "value": to_utc_iso(utcnow())},
        ],
    )
    return _layer_response(layer, "detection-coverage-actors.json")


@router.get("/{actor_id}/navigator-layer")
async def actor_navigator_layer(
    actor_id: str,
    match_mode: MatchMode = Query(
        "coverage",
        description="Which rules count toward each technique's score.",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Downloadable ATT&CK Navigator layer for one actor / software:
    one entry per technique the object uses, score = matching rule
    count at the selected match mode, comment = matching rule titles
    (capped). Techniques with score 0 stay enabled — the zeros are the
    point of the export.
    """
    actor_id = actor_id.upper()
    kind, _ = _actor_type(actor_id)

    await mitre_service.ensure_loaded()
    await actor_context_service.ensure_loaded()
    entity = (
        mitre_service.get_group(actor_id)
        if kind == "group" else mitre_service.get_software(actor_id)
    )
    if entity is None:
        raise HTTPException(status_code=404, detail=f"Unknown actor id: {actor_id}")

    bundle = await actor_score_service.get(db)
    scores_entry = (bundle.groups if kind == "group" else bundle.software)[actor_id]
    technique_ids = sorted({t.upper() for t in entity.get("techniques", [])})

    if match_mode == "coverage":
        technique_scores = {
            tid: bundle.technique_rule_counts.get(tid, 0) for tid in technique_ids
        }
        technique_titles = await _technique_rule_titles(db, technique_ids)
    else:
        ctx = (
            actor_context_service.get_context(actor_id)
            if kind == "group" else None
        )
        names = [entity["name"]] + merge_aliases(
            list(entity.get("aliases", [])), ctx, exclude=entity["name"]
        )
        column = (
            Detection.mitre_groups if kind == "group" else Detection.mitre_software
        )
        dedicated_rows, _ = await _dedicated_rules(db, column, actor_id, names)
        if match_mode == "exact":
            rows = dedicated_rows
        else:  # mention — disjoint from dedicated (issue #34)
            rows, _ = await _referenced_rules(
                db, names, {r[0] for r in dedicated_rows}
            )
        technique_titles = await _technique_rule_titles(
            db, technique_ids, restrict_rows=rows
        )
        technique_scores = {
            tid: len(technique_titles.get(tid, [])) for tid in technique_ids
        }

    weighted = scores_entry.weighted_coverage
    layer = _build_layer(
        name=f"{entity['name']} ({actor_id}) — detection coverage",
        description=(
            f"Techniques used by {entity['name']} per MITRE ATT&CK, scored by "
            f"detection-rule count in the Detection Explorer corpus "
            f"({match_mode} match mode)."
        ),
        technique_scores=technique_scores,
        technique_comments={
            tid: _technique_comment(technique_titles.get(tid, []))
            for tid in technique_ids
        },
        metadata=[
            {"name": "source", "value": "detectionexplorer.io"},
            {"name": "actor", "value": f"{entity['name']} ({actor_id})"},
            {"name": "match_mode", "value": match_mode},
            {
                "name": "weighted_coverage",
                "value": f"{weighted:.4f}" if weighted is not None else "n/a",
            },
            {"name": "generated", "value": to_utc_iso(utcnow())},
        ],
    )
    slug = re.sub(r"[^a-z0-9]+", "-", entity["name"].lower()).strip("-")
    return _layer_response(layer, f"{slug}-{actor_id.lower()}-navigator-layer.json")


@software_router.get("/{software_id}/navigator-layer")
async def software_navigator_layer(
    software_id: str,
    match_mode: MatchMode = Query("coverage"),
    db: AsyncSession = Depends(get_db),
):
    """Alias for /actors/{S-ID}/navigator-layer (documented path)."""
    if not software_id.upper().startswith("S"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid software id: {software_id}. Expected S####.",
        )
    return await actor_navigator_layer(software_id, match_mode, db)


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
    # Per-source breakdown (#18): which vendor covers which of this
    # actor's techniques. One uncapped scan of (source, techniques) for
    # rules tagging any of the actor's techniques, aggregated in Python.
    by_source_per_technique: dict[str, dict[str, int]] = {}
    actor_tids = {t["technique_id"] for t in techniques_used}
    if actor_tids:
        conds = [
            cast(Detection.mitre_techniques, String).ilike(f'%"{tid}"%')
            for tid in actor_tids
        ]
        src_rows = (
            await db.execute(
                select(Detection.source, Detection.mitre_techniques).where(or_(*conds))
            )
        ).all()
        for src, tids in src_rows:
            for tid in tids or []:
                tid_u = str(tid).upper()
                if tid_u in actor_tids:
                    per = by_source_per_technique.setdefault(tid_u, {})
                    per[src] = per.get(src, 0) + 1
    for t in techniques_used:
        t["rule_count_by_source"] = dict(
            sorted(by_source_per_technique.get(t["technique_id"], {}).items())
        )
    coverage_by_source: dict[str, dict] = {}
    for tid, per in by_source_per_technique.items():
        for src, n in per.items():
            entry = coverage_by_source.setdefault(src, {"techniques_covered": 0, "rule_count": 0})
            entry["techniques_covered"] += 1
            entry["rule_count"] += n

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

    # Names for exact-story and mention matching = primary name +
    # aliases, including galaxy synonyms (a rule citing "GOLD SAHARA"
    # counts as mentioning Akira).
    mention_ctx = (
        actor_context_service.get_context(actor_id) if kind == "group" else None
    )
    mention_names = [entity["name"]] + merge_aliases(
        list(entity.get("aliases", [])), mention_ctx, exclude=entity["name"]
    )

    # Match counts across all three modes — always populated so the
    # UI can render the switcher without a round-trip. Dedicated and
    # referenced are DISJOINT (issue #34): dedicated = id-tag / story
    # label / name-in-title; referenced = everything else that names
    # the actor, minus dedicated.
    column = Detection.mitre_groups if kind == "group" else Detection.mitre_software
    dedicated_rows, dedicated_reasons = await _dedicated_rules(
        db, column, actor_id, mention_names
    )
    referenced_rows, referenced_reasons = await _referenced_rules(
        db, mention_names, {r[0] for r in dedicated_rows}
    )
    exact_count = len(dedicated_rows)
    mention_count = len(referenced_rows)
    coverage_ids = [t["technique_id"] for t in techniques_used]
    coverage_count = await _count_matches(db, Detection.mitre_techniques, coverage_ids)

    # Fetch rules for the SELECTED mode
    if match_mode == "exact":
        rule_rows, rule_reasons = dedicated_rows[:RULES_LIMIT], dedicated_reasons
    elif match_mode == "coverage":
        rule_rows = await _rules_matching_ids(db, Detection.mitre_techniques, coverage_ids)
        rule_reasons = {}
    else:  # mention
        rule_rows, rule_reasons = referenced_rows[:RULES_LIMIT], referenced_reasons

    rules = [_serialize_rule(r, rule_reasons) for r in rule_rows]
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
        # {source: {techniques_covered, rule_count}} -- the gap heatmap
        # row for this actor (#18). Sources with no matching rules are
        # absent; the UI renders those as gaps.
        "coverage_by_source": dict(sorted(coverage_by_source.items())),
        associated_key: associated,
        "match_counts": {
            "exact": exact_count,
            "coverage": coverage_count,
            "mention": mention_count,
        },
        "match_mode": match_mode,
        "rules": rules,
    }
