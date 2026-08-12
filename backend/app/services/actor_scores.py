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
import re
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.actor_context import actor_context_service, merge_aliases
from app.services.mitre import mitre_service

logger = logging.getLogger(__name__)

# Parity with actors._rules_mentioning: names shorter than this are
# too substring-happy to count as mentions.
MIN_MENTION_NAME_LEN = 3


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
    # Rules whose title/description/tags mention the entity's name or
    # an alias as a whole word (same matcher as the detail page's
    # mention mode). Zero exact rules + many mentions = vendor content
    # exists but isn't ATT&CK-tagged — notable.
    mention_count: int = 0


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


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _mention_names(entity: dict, kind: str) -> list[str]:
    """Name + aliases used for mention matching — merged with galaxy
    synonyms for groups, mirroring the detail endpoint."""
    ctx = (
        actor_context_service.get_context(entity["id"]) if kind == "group" else None
    )
    names = [entity["name"]] + merge_aliases(
        list(entity.get("aliases", [])), ctx, exclude=entity["name"]
    )
    return [n for n in names if len(n) >= MIN_MENTION_NAME_LEN]


def compute_mention_counts(
    rule_texts: list[str],
    entity_names: dict[str, list[str]],
) -> dict[str, int]:
    """Rules mentioning each entity by name/alias as a whole word.

    Semantics match actors._rules_mentioning (case-insensitive \\b
    regex), but scanning every rule for every one of ~5,000 names is
    quadratic — so each name declares a required token (its longest
    alphanumeric run), a token index maps rule text -> candidate
    names, and only candidates run the precise regex.
    """
    # name -> (entity ids using it, required token, compiled regex)
    by_name: dict[str, dict] = {}
    token_to_names: dict[str, set[str]] = {}
    for eid, names in entity_names.items():
        for name in names:
            key = name.lower()
            entry = by_name.get(key)
            if entry is None:
                tokens = _TOKEN_RE.findall(key)
                if not tokens:
                    continue
                required = max(tokens, key=len)
                entry = {
                    "ids": set(),
                    "regex": re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE),
                }
                by_name[key] = entry
                token_to_names.setdefault(required, set()).add(key)
            entry["ids"].add(eid)

    counts: dict[str, int] = {eid: 0 for eid in entity_names}
    for text in rule_texts:
        if not text:
            continue
        text_tokens = set(_TOKEN_RE.findall(text.lower()))
        hit_ids: set[str] = set()
        for token in text_tokens:
            for key in token_to_names.get(token, ()):
                entry = by_name[key]
                if entry["ids"] <= hit_ids:
                    continue  # every owner already matched via another name
                if entry["regex"].search(text):
                    hit_ids |= entry["ids"]
        for eid in hit_ids:
            counts[eid] += 1
    return counts


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
        return (
            row[0],
            str(row[1]),
            mitre_service.get_stats()["last_fetch"],
            # Galaxy joins feed mention aliases — recompute when the
            # galaxy version moves.
            actor_context_service.get_stats().get("version"),
        )

    def invalidate(self) -> None:
        self._bundle = None

    async def get(self, db: AsyncSession) -> ScoreBundle:
        await mitre_service.ensure_loaded()
        await actor_context_service.ensure_loaded()
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
            Detection.title,
            Detection.description,
            Detection.tags,
        )
        rows = (await db.execute(q)).all()

        technique_rule_counts: dict[str, int] = {}
        exact_groups: dict[str, dict] = {}
        exact_software: dict[str, dict] = {}
        rule_texts: list[str] = []
        for source, rgroups, rsoftware, rtechs, title, description, tags in rows:
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
            rule_texts.append(" ".join([
                title or "",
                description or "",
                " ".join(t for t in (tags or []) if isinstance(t, str)),
            ]))

        entity_names = {
            gid: _mention_names(g, "group")
            for gid, g in mitre_service.get_all_groups().items()
        }
        entity_names.update({
            sid: _mention_names(s, "software")
            for sid, s in mitre_service.get_all_software().items()
        })
        mention_counts = compute_mention_counts(rule_texts, entity_names)

        groups = {
            gid: _score_entity(g, technique_rule_counts, exact_groups)
            for gid, g in mitre_service.get_all_groups().items()
        }
        software = {
            sid: _score_entity(s, technique_rule_counts, exact_software)
            for sid, s in mitre_service.get_all_software().items()
        }
        for eid, count in mention_counts.items():
            entry = groups.get(eid) or software.get(eid)
            if entry:
                entry.mention_count = count
        logger.info(
            "Recomputed actor scores: %d groups, %d software, %d covered "
            "techniques, %d entities with mentions",
            len(groups), len(software),
            sum(1 for c in technique_rule_counts.values() if c > 0),
            sum(1 for c in mention_counts.values() if c > 0),
        )
        return ScoreBundle(
            fingerprint=fp,
            technique_rule_counts=technique_rule_counts,
            groups=groups,
            software=software,
        )


# Global singleton, matching the mitre_service pattern.
actor_score_service = ActorScoreService()
