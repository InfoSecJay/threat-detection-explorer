"""Threat Actors + Software (ATT&CK Groups + Software) API routes.

MVP scope: enumerate + drill into the actors/software our corpus has
coverage for, via the `mitre_groups` / `mitre_software` columns
populated during Sigma + LOLRMM ingestion. Display names come from
`app.services.mitre_lookup`.

A future enhancement (roadmap) will extend `mitre_service` to load
ATT&CK intrusion-set + malware STIX objects so we can also render
"gaps" — techniques an actor is known to use but that we have zero
rules for. This module is the scoped-to-what-we-have counterpart.
"""

from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.detection import Detection
from app.services.mitre_lookup import resolve_group, resolve_software

router = APIRouter(prefix="/actors", tags=["actors"])


@router.get("")
async def list_actors(
    limit: int = Query(200, ge=10, le=500, description="Max entries per list"),
    db: AsyncSession = Depends(get_db),
):
    """List every ATT&CK Group + Software with rule coverage.

    Returns two lists (`groups`, `software`), each sorted by rule
    count descending. Each entry includes display name, aliases (for
    groups) or type (for software), rule count, distinct-technique
    count, and the sources contributing coverage.

    Actor/software rows without any coverage in our corpus are
    omitted — this is the "who are we chasing?" list, not the full
    ATT&CK catalog.
    """
    q = select(
        Detection.source,
        Detection.mitre_groups,
        Detection.mitre_software,
        Detection.mitre_techniques,
    )
    rows = (await db.execute(q)).all()

    groups: dict[str, dict] = {}
    software: dict[str, dict] = {}

    for source, rule_groups, rule_software, rule_techniques in rows:
        techs = set(rule_techniques or [])
        for gid in rule_groups or []:
            gid_u = gid.upper()
            entry = groups.setdefault(
                gid_u,
                {"id": gid_u, "rule_count": 0, "techniques": set(), "sources": set()},
            )
            entry["rule_count"] += 1
            entry["techniques"].update(techs)
            entry["sources"].add(source)
        for sid in rule_software or []:
            sid_u = sid.upper()
            entry = software.setdefault(
                sid_u,
                {"id": sid_u, "rule_count": 0, "techniques": set(), "sources": set()},
            )
            entry["rule_count"] += 1
            entry["techniques"].update(techs)
            entry["sources"].add(source)

    def _finish_group(entry: dict) -> dict:
        resolved = resolve_group(entry["id"])
        return {
            "id": entry["id"],
            "name": resolved["name"],
            "aliases": resolved["aliases"],
            "rule_count": entry["rule_count"],
            "technique_count": len(entry["techniques"]),
            "sources": sorted(entry["sources"]),
        }

    def _finish_software(entry: dict) -> dict:
        resolved = resolve_software(entry["id"])
        return {
            "id": entry["id"],
            "name": resolved["name"],
            "type": resolved["type"],
            "rule_count": entry["rule_count"],
            "technique_count": len(entry["techniques"]),
            "sources": sorted(entry["sources"]),
        }

    sorted_groups = sorted(groups.values(), key=lambda x: (-x["rule_count"], x["id"]))[:limit]
    sorted_software = sorted(software.values(), key=lambda x: (-x["rule_count"], x["id"]))[:limit]

    return {
        "groups": [_finish_group(g) for g in sorted_groups],
        "software": [_finish_software(s) for s in sorted_software],
    }


@router.get("/{actor_id}")
async def get_actor(
    actor_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Actor / software detail — metadata + rules grouped by technique.

    `actor_id` is a raw ATT&CK ID: `G####` for groups, `S####` for
    software. Case-insensitive on input; normalized to uppercase for
    matching + response.

    Returns metadata (display name, aliases/type, MITRE URL), the
    aggregate rule count + source list, and two views of the rules:
      - `by_technique`: rules grouped by MITRE technique they map to
      - `rules`: flat list of matching rules with core fields for
        rendering a table.

    A single rule tagged with 3 techniques appears once in `rules`
    and contributes to 3 entries under `by_technique` — that's the
    right shape for the coverage question.
    """
    actor_id = actor_id.upper()
    if not actor_id.startswith(("G", "S")):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid actor id: {actor_id}. Expected G#### or S####.",
        )

    is_group = actor_id.startswith("G")
    column = Detection.mitre_groups if is_group else Detection.mitre_software

    # Cast + ilike is portable across SQLite + Postgres, same pattern
    # search service uses for other JSON-list filters.
    from sqlalchemy import String, cast
    q = select(
        Detection.id,
        Detection.rule_id,
        Detection.title,
        Detection.source,
        Detection.severity,
        Detection.language,
        Detection.mitre_techniques,
        Detection.platforms,
        Detection.rule_created_date,
    ).where(cast(column, String).ilike(f'%"{actor_id}"%'))
    rows = (await db.execute(q)).all()

    if not rows:
        # Still return a 200 with an empty payload — the actor could be
        # known in the lookup table but not yet covered by any rule.
        # UI shows a "no rules yet" empty state rather than a 404.
        pass

    rules = []
    by_technique: dict[str, dict] = {}
    sources_set: set[str] = set()

    for (rid, rule_id, title, source, severity, language, techniques,
         platforms, created_date) in rows:
        techs = techniques or []
        rules.append({
            "id": rid,
            "rule_id": rule_id,
            "title": title,
            "source": source,
            "severity": severity,
            "language": language,
            "techniques": techs,
            "platforms": platforms or [],
            "date": created_date.isoformat() if created_date else None,
        })
        sources_set.add(source)
        for tech_id in techs:
            entry = by_technique.setdefault(
                tech_id,
                {"technique_id": tech_id, "rule_count": 0, "sources": set()},
            )
            entry["rule_count"] += 1
            entry["sources"].add(source)

    if is_group:
        resolved = resolve_group(actor_id)
        metadata = {
            "id": actor_id,
            "kind": "group",
            "name": resolved["name"],
            "aliases": resolved["aliases"],
            "mitre_url": f"https://attack.mitre.org/groups/{actor_id}/",
        }
    else:
        resolved = resolve_software(actor_id)
        metadata = {
            "id": actor_id,
            "kind": "software",
            "name": resolved["name"],
            "type": resolved["type"],
            "mitre_url": f"https://attack.mitre.org/software/{actor_id}/",
        }

    return {
        **metadata,
        "rule_count": len(rules),
        "technique_count": len(by_technique),
        "sources": sorted(sources_set),
        "by_technique": sorted(
            (
                {**v, "sources": sorted(v["sources"])}
                for v in by_technique.values()
            ),
            key=lambda x: (-x["rule_count"], x["technique_id"]),
        ),
        "rules": sorted(
            rules,
            key=lambda x: (x["source"], x["title"]),
        ),
    }
