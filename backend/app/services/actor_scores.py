"""Precomputed detection scores for ATT&CK Groups + Software.

Replaces the raw "N of M techniques covered" ranking, which measured
how *common* an actor's techniques are rather than how well we detect
that actor (MuddyWater 96%, Winnti 100%, everything flat). Scores here
weight each technique by distinctiveness (`weight_t = log(N / n_t)`,
computed by the MITRE service from the actor->technique matrix):

    covered(t)        = >=1 rule in the corpus tags technique t
                        (COVERAGE match mode)
    weighted_coverage = covered weight mass / total weight mass
    gap_count         = uncovered technique count (human-readable)
    weighted_gap      = uncovered weight mass — the primary ranking
                        key: how much detection work is outstanding,
                        weighted by how much it matters
    exact_rule_count  = rules tagged with the actor's own ATT&CK ID

Everything is materialized in ONE corpus scan and cached in-memory.
Cache validity is probed per request with a cheap fingerprint query
(COUNT + MAX(updated_at) over detections, plus the ATT&CK catalog
fetch time) so list endpoints never re-run the scan unless an ingest
or catalog refresh actually changed something.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.mitre import mitre_service

logger = logging.getLogger(__name__)


@dataclass
class EntityScores:
    """Scores for one group or software entry."""

    exact_rule_count: int
    sources: list[str]
    technique_count: int
    covered_technique_count: int
    # None when the entity has no techniques to score (or no technique
    # carries an actor weight) — the UI must degrade, not show 0%.
    weighted_coverage: Optional[float]
    gap_count: int
    weighted_gap: float


@dataclass
class ScoreBundle:
    """Everything the actors endpoints need, from one corpus scan."""

    fingerprint: tuple
    # technique id -> number of rules tagging it (COVERAGE overlay)
    technique_rule_counts: dict[str, int]
    groups: dict[str, EntityScores]
    software: dict[str, EntityScores]


def _score_entity(
    entity: dict,
    technique_rule_counts: dict[str, int],
    exact: dict[str, dict],
) -> EntityScores:
    techniques = [t.upper() for t in entity.get("techniques", [])]
    covered = 0
    gap_count = 0
    covered_weight = 0.0
    total_weight = 0.0
    uncovered_weight = 0.0

    for tid in techniques:
        tech = mitre_service.get_technique(tid)
        weight = tech.get("actor_weight") if tech else None
        is_covered = technique_rule_counts.get(tid, 0) > 0
        if is_covered:
            covered += 1
        else:
            gap_count += 1
        # Techniques outside the weight corpus (no group uses them —
        # possible for software) are excluded from the weighted sums,
        # mirroring their exclusion from the weight computation.
        if weight is None:
            continue
        total_weight += weight
        if is_covered:
            covered_weight += weight
        else:
            uncovered_weight += weight

    if total_weight > 0:
        weighted_coverage: Optional[float] = covered_weight / total_weight
    elif techniques:
        # Degenerate: every technique weightless (all used by every
        # actor, or none in the weight corpus). Fall back to the raw
        # ratio rather than reporting nothing.
        weighted_coverage = covered / len(techniques)
    else:
        weighted_coverage = None

    ex = exact.get(entity["id"], {})
    return EntityScores(
        exact_rule_count=ex.get("rule_count", 0),
        sources=sorted(ex.get("sources", set())),
        technique_count=len(techniques),
        covered_technique_count=covered,
        weighted_coverage=weighted_coverage,
        gap_count=gap_count,
        weighted_gap=uncovered_weight,
    )


class ActorScoreService:
    """In-memory materialized scores, recomputed only when the corpus
    or the ATT&CK catalog actually changes."""

    def __init__(self) -> None:
        self._bundle: Optional[ScoreBundle] = None

    async def _fingerprint(self, db: AsyncSession) -> tuple:
        row = (
            await db.execute(
                select(func.count(Detection.id), func.max(Detection.updated_at))
            )
        ).one()
        return (row[0], str(row[1]), mitre_service.get_stats()["last_fetch"])

    def invalidate(self) -> None:
        self._bundle = None

    async def get(self, db: AsyncSession) -> ScoreBundle:
        await mitre_service.ensure_loaded()
        fp = await self._fingerprint(db)
        if self._bundle is not None and self._bundle.fingerprint == fp:
            return self._bundle
        self._bundle = await self._compute(db, fp)
        return self._bundle

    async def _compute(self, db: AsyncSession, fp: tuple) -> ScoreBundle:
        q = select(
            Detection.source,
            Detection.mitre_groups,
            Detection.mitre_software,
            Detection.mitre_techniques,
        )
        rows = (await db.execute(q)).all()

        technique_rule_counts: dict[str, int] = {}
        exact_groups: dict[str, dict] = {}
        exact_software: dict[str, dict] = {}
        for source, rgroups, rsoftware, rtechs in rows:
            for gid in rgroups or []:
                e = exact_groups.setdefault(gid.upper(), {"rule_count": 0, "sources": set()})
                e["rule_count"] += 1
                e["sources"].add(source)
            for sid in rsoftware or []:
                e = exact_software.setdefault(sid.upper(), {"rule_count": 0, "sources": set()})
                e["rule_count"] += 1
                e["sources"].add(source)
            for tid in rtechs or []:
                tid_u = tid.upper()
                technique_rule_counts[tid_u] = technique_rule_counts.get(tid_u, 0) + 1

        groups = {
            gid: _score_entity(g, technique_rule_counts, exact_groups)
            for gid, g in mitre_service.get_all_groups().items()
        }
        software = {
            sid: _score_entity(s, technique_rule_counts, exact_software)
            for sid, s in mitre_service.get_all_software().items()
        }
        logger.info(
            "Recomputed actor scores: %d groups, %d software, %d covered techniques",
            len(groups), len(software),
            sum(1 for c in technique_rule_counts.values() if c > 0),
        )
        return ScoreBundle(
            fingerprint=fp,
            technique_rule_counts=technique_rule_counts,
            groups=groups,
            software=software,
        )


# Global singleton, matching the mitre_service pattern.
actor_score_service = ActorScoreService()
