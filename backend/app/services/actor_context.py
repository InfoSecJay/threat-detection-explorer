"""Threat-actor context enrichment from the MISP galaxy (CC0).

ATT&CK carries no structured origin, motivation, or targeting data.
This service joins the MISP `threat-actor` galaxy clusters onto ATT&CK
groups and exposes, per G-ID:

    origin_country    ISO-2 from meta.country
    motivations[]     normalized enum: espionage | ransomware |
                      financial-crime | destructive | hacktivism | unknown
    target_sectors[]  normalized fixed taxonomy (telecommunications
                      explicitly included)
    target_regions[]  victim countries rolled up to regions
    target_countries[] raw victim list (detail page)
    aliases[]         galaxy synonyms (union with ATT&CK aliases happens
                      at the API layer, deduped on normalized form)
    references[]      meta.refs URLs

Join strategy: alias match, not name match. Both sides are normalized
(lowercase, strip non-alphanumerics) into a many-to-many index; an
ATT&CK actor matches a cluster when any normalized ATT&CK name/alias
equals any normalized cluster value / synonym. Ambiguous matches (one
actor -> several clusters) are logged and resolved via a small
hardcoded override map; unresolved ambiguity yields NO enrichment
rather than a silent first-pick.

Source: https://github.com/MISP/misp-galaxy (clusters/threat-actor.json),
vendored at backend/vendored/misp_galaxy_threat_actor.json. A network
refresh runs on the same 24h cadence as the ATT&CK ingest, cached to
data/misp_galaxy_threat_actor.json; the vendored copy is the fallback
so the feature never depends on GitHub availability.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

from app.services.mitre import mitre_service
from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

GALAXY_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)
VENDORED_FILE = Path(__file__).resolve().parents[2] / "vendored" / "misp_galaxy_threat_actor.json"
CACHE_FILE = Path("data/misp_galaxy_threat_actor.json")
CACHE_DURATION_HOURS = 24  # same cadence as the ATT&CK ingest

# ── Ambiguity overrides ────────────────────────────────────────────
# G-ID -> galaxy cluster uuid. Filled for actors whose aliases match
# more than one cluster; everything else resolves automatically. An
# override of None means "known ambiguous, enrich with nothing".
AMBIGUITY_OVERRIDES: dict[str, Optional[str]] = {
    # Vetted 2026-08-11 against galaxy version 349. Rule of thumb:
    # prefer the cluster that IS this actor at ATT&CK's granularity
    # (Andariel -> Silent Chollima, not the umbrella Lazarus cluster),
    # then the richer CFR metadata when two clusters describe the
    # same actor under different vendor names.
    "G0004": "3501fbf2-098f-47e7-be6a-6b0ff5742ce8",  # Ke3chang -> APT15
    "G0010": "fa80877c-f509-4daf-8b62-20aba1635f68",  # Turla -> Turla
    "G0016": "b2056ff0-00b9-482e-b11c-c771daa5f28a",  # APT29 -> APT29
    "G0030": "32fafa69-fe3c-49db-afd4-aac2664bcf0d",  # Lotus Blossom -> LOTUS PANDA
    "G0034": "f512de42-f76b-40d2-9923-59e7dbdfec35",  # Sandworm Team -> Sandworm
    "G0040": "18d473a5-831b-47a5-97a1-a32156299825",  # Patchwork -> QUILTED TIGER
    "G0049": "42be2a84-5a5c-4c6d-9864-3f09d75bb0ba",  # OilRig -> OilRig (Cleaver is G0003)
    "G0059": "f98bac6b-12fd-4cad-be84-c84666932232",  # Magic Hound -> Charming Kitten
    "G0082": "d8e1762a-0063-48c2-9ea1-8d176d14b70f",  # APT38 -> STARDUST CHOLLIMA (not umbrella Lazarus)
    "G0092": "03c80674-35f8-4fe0-be2b-226ed0fcd69f",  # TA505 -> TA505
    "G0094": "bcaaad6f-0597-4b89-b69b-84a6be2b7bc3",  # Kimsuky -> Kimsuky
    "G0102": "bdf4fe4f-af8a-495f-a719-cf175cecda1f",  # Wizard Spider -> WIZARD SPIDER
    "G0112": "cbbbfc82-9294-11e9-8e19-2bc14137b25b",  # Windshift -> WindShift (Bahamut is G0842)
    "G0115": "262c8537-1cdb-4297-aa3e-1410164160bf",  # GOLD SOUTHFIELD -> GOLD SOUTHFIELD
    "G0119": "658314bc-3bb8-48d2-913a-c528607b75c8",  # Indrik Spider -> INDRIK SPIDER
    "G0123": "cf421ce6-ddfe-419a-bc65-6a9fc953232a",  # Volatile Cedar -> Volatile Cedar
    "G0129": "78bf726c-a9e6-11e8-9e43-77249a2f7339",  # Mustang Panda -> MUSTANG PANDA
    "G0130": "ba724df5-9aa0-45ca-8e0e-7101c208ae48",  # Ajax Security Team -> Flying Kitten
    "G0138": "245c8dde-ed42-4c49-b48b-634e3e21bdd7",  # Andariel -> Silent Chollima (not umbrella Lazarus)
    "G1003": "a5f64c1a-c829-4855-903d-e0ff2098b2d7",  # Ember Bear -> DEV-0586 (richer CFR meta)
    "G1020": "3ce9610b-2435-4c41-80d1-3f95a5ff2984",  # Mustard Tempest -> Mustard Tempest
    "G1023": "a47b79ae-7a0c-4308-9efc-294af19cc795",  # APT5 -> APT5
    "G1028": "0cfff0f4-868c-40a1-b9b4-0d153c0b33b6",  # APT-C-23 -> AridViper
    "G1033": "fbd279ab-c095-48dc-ba48-4bece3dd5b0f",  # Star Blizzard -> Callisto (richer meta)
    "G1034": "171d0590-be92-443f-addb-af5dc2a8034d",  # Daggerfly -> Evasive Panda (richer CFR meta)
    "G1049": "afe5526e-e5e4-4b05-bc69-2bfb6785fc7e",  # AppleJeus -> UNC4736 (3CX, not umbrella Lazarus)
    "G1052": "b2765bd8-1200-4df5-a9d3-72a7b679dcdb",  # Contagious Interview -> Contagious Interview
    "G1055": "3682a08e-c1d9-4dff-ae08-774883dddba6",  # VOID MANTICORE -> BANISHED KITTEN (richer CFR meta)
}

# ── Normalization tables ───────────────────────────────────────────

MOTIVATION_MAP = {
    # cfr-type-of-incident values
    "espionage": "espionage",
    "denial of service": "destructive",
    "sabotage": "destructive",
    "financial theft": "financial-crime",
    "financial crime": "financial-crime",
    "business email compromise": "financial-crime",
    "extortion": "ransomware",
    "defacement": "hacktivism",
    "information operations": "hacktivism",
    # meta.motive values (free-ish text, matched after normalization)
    "cybercrime": "financial-crime",
    "hacktivists-nationalists": "hacktivism",
    "hacktivism": "hacktivism",
}

# Keyword fallback for free-text motive strings.
MOTIVE_KEYWORDS = [
    (re.compile(r"\bransom", re.I), "ransomware"),
    (re.compile(r"\bespionage\b", re.I), "espionage"),
    (re.compile(r"\bhacktiv|\bnationalist", re.I), "hacktivism"),
    (re.compile(r"\bfinancial|\bcybercrime\b", re.I), "financial-crime"),
    (re.compile(r"\bsabotage\b|\bdestruct", re.I), "destructive"),
]

# High-precision heuristic: a threat-actor cluster whose description
# names ransomware operations is a ransomware actor (word-boundary
# match; the corpus has no counter-examples where the word appears in
# a defensive sense on an actor cluster).
RANSOMWARE_DESC_RE = re.compile(r"\bransomware\b", re.I)

SECTOR_MAP = {
    "government": "government",
    "military": "defense",
    "defense": "defense",
    "defense industrial base": "defense",
    "energy": "energy",
    "oil and gas": "energy",
    "healthcare": "healthcare",
    "health care": "healthcare",
    "pharmaceuticals": "healthcare",
    "finance": "finance",
    "financial": "finance",
    "banking": "finance",
    "cryptocurrency": "finance",
    "telecommunications": "telecommunications",
    "telecoms": "telecommunications",
    "telecomms": "telecommunications",
    "telecom": "telecommunications",
    "high-tech": "technology",
    "information technology": "technology",
    "technology": "technology",
    "software": "technology",
    "media": "media",
    "media and entertainment": "media",
    "education": "education",
    "academia": "education",
    "civil society": "civil-society",
    "ngos": "civil-society",
    "think tanks": "civil-society",
    "transportation": "transportation",
    "transportation systems": "transportation",
    "aviation": "transportation",
    "automotive": "manufacturing",
    "manufacturing": "manufacturing",
    "industrial": "manufacturing",
    "legal": "legal",
    "law firms": "legal",
    "retail": "retail",
    "hospitality": "retail",
    "private sector": "private-sector",
    "business": "private-sector",
    "critical infrastructure": "critical-infrastructure",
    "electoral": "government",
    "elections": "government",
}

REGION_MAP = {
    # North America
    "united states": "north-america", "canada": "north-america", "mexico": "north-america",
    # South / Latin America
    "brazil": "south-america", "argentina": "south-america", "chile": "south-america",
    "colombia": "south-america", "peru": "south-america", "venezuela": "south-america",
    "ecuador": "south-america", "bolivia": "south-america", "uruguay": "south-america",
    "panama": "south-america", "costa rica": "south-america", "guatemala": "south-america",
    "latin america": "south-america",
    # Europe
    "germany": "europe", "united kingdom": "europe", "france": "europe", "italy": "europe",
    "spain": "europe", "poland": "europe", "netherlands": "europe", "belgium": "europe",
    "switzerland": "europe", "sweden": "europe", "norway": "europe", "denmark": "europe",
    "finland": "europe", "austria": "europe", "czech republic": "europe", "czechia": "europe",
    "hungary": "europe", "romania": "europe", "bulgaria": "europe", "greece": "europe",
    "portugal": "europe", "ireland": "europe", "lithuania": "europe", "latvia": "europe",
    "estonia": "europe", "slovakia": "europe", "slovenia": "europe", "croatia": "europe",
    "serbia": "europe", "montenegro": "europe", "north macedonia": "europe", "macedonia": "europe",
    "albania": "europe", "bosnia and herzegovina": "europe", "cyprus": "europe", "malta": "europe",
    "iceland": "europe", "luxembourg": "europe", "moldova": "europe", "europe": "europe",
    "european union": "europe", "vatican": "europe", "vatican city": "europe",
    # CIS / Eastern Europe & Central Asia
    "russia": "cis", "ukraine": "cis", "belarus": "cis", "georgia": "cis",
    "armenia": "cis", "azerbaijan": "cis", "kazakhstan": "cis", "kyrgyzstan": "cis",
    "uzbekistan": "cis", "tajikistan": "cis", "turkmenistan": "cis", "central asia": "cis",
    # Middle East
    "israel": "middle-east", "iran": "middle-east", "iraq": "middle-east",
    "saudi arabia": "middle-east", "united arab emirates": "middle-east",
    "qatar": "middle-east", "kuwait": "middle-east", "bahrain": "middle-east",
    "oman": "middle-east", "yemen": "middle-east", "jordan": "middle-east",
    "lebanon": "middle-east", "syria": "middle-east", "turkey": "middle-east",
    "palestine": "middle-east", "middle east": "middle-east", "afghanistan": "middle-east",
    # Africa
    "egypt": "africa", "libya": "africa", "morocco": "africa", "algeria": "africa",
    "tunisia": "africa", "sudan": "africa", "south africa": "africa", "nigeria": "africa",
    "kenya": "africa", "ethiopia": "africa", "uganda": "africa", "ghana": "africa",
    "africa": "africa",
    # East Asia
    "china": "east-asia", "japan": "east-asia", "south korea": "east-asia",
    "north korea": "east-asia", "taiwan": "east-asia", "hong kong": "east-asia",
    "mongolia": "east-asia", "macau": "east-asia",
    # South Asia
    "india": "south-asia", "pakistan": "south-asia", "bangladesh": "south-asia",
    "sri lanka": "south-asia", "nepal": "south-asia", "bhutan": "south-asia",
    "maldives": "south-asia",
    # Southeast Asia
    "vietnam": "southeast-asia", "thailand": "southeast-asia", "malaysia": "southeast-asia",
    "singapore": "southeast-asia", "indonesia": "southeast-asia", "philippines": "southeast-asia",
    "myanmar": "southeast-asia", "cambodia": "southeast-asia", "laos": "southeast-asia",
    "brunei": "southeast-asia", "southeast asia": "southeast-asia",
    # Oceania
    "australia": "oceania", "new zealand": "oceania",
}


def normalize_alias(name: str) -> str:
    """Join key: lowercase, strip everything non-alphanumeric."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def normalize_motivations(meta: dict, description: str = "") -> list[str]:
    out: list[str] = []

    def _add(val: Optional[str]) -> None:
        if val and val not in out:
            out.append(val)

    incidents = meta.get("cfr-type-of-incident") or []
    if isinstance(incidents, str):
        incidents = [incidents]
    for raw in incidents:
        _add(MOTIVATION_MAP.get(raw.strip().lower()))

    motive = meta.get("motive")
    motives = motive if isinstance(motive, list) else ([motive] if motive else [])
    for raw in motives:
        mapped = MOTIVATION_MAP.get(str(raw).strip().lower())
        if mapped:
            _add(mapped)
            continue
        for pattern, val in MOTIVE_KEYWORDS:
            if pattern.search(str(raw)):
                _add(val)

    if RANSOMWARE_DESC_RE.search(description or ""):
        _add("ransomware")

    return out


def normalize_sectors(meta: dict) -> list[str]:
    out: list[str] = []
    raw_values = list(meta.get("cfr-target-category") or []) + list(
        meta.get("targeted-sector") or []
    )
    for raw in raw_values:
        mapped = SECTOR_MAP.get(str(raw).strip().lower())
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def rollup_regions(countries: list[str]) -> list[str]:
    out: list[str] = []
    for c in countries:
        region = REGION_MAP.get(str(c).strip().lower())
        if region and region not in out:
            out.append(region)
    return out


class ActorContextService:
    """Loads galaxy clusters, joins them onto ATT&CK groups by alias."""

    def __init__(self) -> None:
        self._clusters: list[dict] = []
        self._version: Optional[int] = None
        self._contexts: dict[str, dict] = {}
        self._alias_to_gids: dict[str, list[str]] = {}
        self._joined_for: Optional[tuple] = None
        self._last_fetch: Optional[datetime] = None
        self._loaded = False

    # ── Loading ────────────────────────────────────────────────────

    async def ensure_loaded(self) -> None:
        if not self._loaded:
            if not self._load_local():
                await self.refresh()
        elif self._is_stale():
            # Same 24h cadence as the ATT&CK ingest. A vendored-pin
            # load has no fetch time and counts as stale, so the first
            # request after that kicks off a network refresh.
            await self.refresh()
        self._ensure_joined()

    def _is_stale(self) -> bool:
        return self._last_fetch is None or utcnow() - self._last_fetch > timedelta(
            hours=CACHE_DURATION_HOURS
        )

    def _load_local(self) -> bool:
        """Cache file if fresh, else the vendored pin."""
        for path in (CACHE_FILE, VENDORED_FILE):
            if not path.exists():
                continue
            if path == CACHE_FILE:
                age = utcnow() - datetime.fromtimestamp(path.stat().st_mtime)
                if age > timedelta(hours=CACHE_DURATION_HOURS):
                    continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._clusters = data.get("values", [])
                self._version = data.get("version")
                self._last_fetch = (
                    datetime.fromtimestamp(path.stat().st_mtime)
                    if path == CACHE_FILE else None
                )
                self._loaded = True
                logger.info(
                    "Loaded MISP galaxy from %s: %d clusters (version %s)",
                    path.name, len(self._clusters), self._version,
                )
                return True
            except Exception as e:
                logger.warning("Failed to load MISP galaxy from %s: %s", path, e)
        return False

    async def refresh(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(GALAXY_URL)
                resp.raise_for_status()
                data = resp.json()
            if not data.get("values"):
                raise ValueError("galaxy payload has no values")
            self._clusters = data["values"]
            self._version = data.get("version")
            self._last_fetch = utcnow()
            self._loaded = True
            self._joined_for = None
            try:
                CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                CACHE_FILE.write_text(json.dumps(data), encoding="utf-8")
            except Exception as e:
                logger.warning("Failed to cache MISP galaxy: %s", e)
            logger.info(
                "Fetched MISP galaxy: %d clusters (version %s)",
                len(self._clusters), self._version,
            )
            return True
        except Exception as e:
            logger.error("Failed to fetch MISP galaxy: %s", e)
            # Back off — don't re-hit the network on every request.
            self._last_fetch = utcnow()
            if not self._loaded:
                # Vendored pin regardless of staleness — never empty.
                if VENDORED_FILE.exists():
                    data = json.loads(VENDORED_FILE.read_text(encoding="utf-8"))
                    self._clusters = data.get("values", [])
                    self._version = data.get("version")
                    self._loaded = True
            return False

    # ── Join ───────────────────────────────────────────────────────

    def _ensure_joined(self) -> None:
        groups = mitre_service.get_all_groups()
        fingerprint = (self._version, len(self._clusters), len(groups))
        if self._joined_for == fingerprint or not groups:
            return
        self._join(groups)
        self._joined_for = fingerprint

    def _join(self, groups: dict[str, dict]) -> None:
        # Cluster alias index: normalized value/synonym -> cluster idx
        cluster_index: dict[str, list[int]] = {}
        for i, cluster in enumerate(self._clusters):
            names = [cluster.get("value", "")] + list(
                (cluster.get("meta") or {}).get("synonyms") or []
            )
            for name in names:
                key = normalize_alias(name)
                if not key:
                    continue
                bucket = cluster_index.setdefault(key, [])
                if i not in bucket:
                    bucket.append(i)

        contexts: dict[str, dict] = {}
        alias_to_gids: dict[str, list[str]] = {}
        ambiguous: list[str] = []

        for gid, g in groups.items():
            attack_names = [g.get("name", "")] + list(g.get("aliases") or [])
            for name in attack_names:
                key = normalize_alias(name)
                if key:
                    bucket = alias_to_gids.setdefault(key, [])
                    if gid not in bucket:
                        bucket.append(gid)

            matched: list[int] = []
            for name in attack_names:
                for idx in cluster_index.get(normalize_alias(name), []):
                    if idx not in matched:
                        matched.append(idx)

            if not matched:
                continue
            if len(matched) > 1:
                uuids = [self._clusters[i].get("uuid") for i in matched]
                override = AMBIGUITY_OVERRIDES.get(gid, "__missing__")
                if override == "__missing__":
                    ambiguous.append(
                        f"{gid} ({g.get('name')}) -> "
                        + ", ".join(
                            f"{self._clusters[i].get('value')}[{self._clusters[i].get('uuid')}]"
                            for i in matched
                        )
                    )
                    continue
                if override is None:
                    continue
                matched = [
                    i for i in matched if self._clusters[i].get("uuid") == override
                ]
                if not matched:
                    logger.warning(
                        "Ambiguity override for %s points at uuid %s not in match set",
                        gid, override,
                    )
                    continue

            cluster = self._clusters[matched[0]]
            meta = cluster.get("meta") or {}
            victims = [str(v) for v in (meta.get("cfr-suspected-victims") or [])]
            synonyms = [s for s in (meta.get("synonyms") or []) if s]
            cluster_value = cluster.get("value", "")
            galaxy_aliases = [cluster_value] + synonyms if cluster_value else synonyms

            contexts[gid] = {
                "origin_country": (meta.get("country") or None),
                "motivations": normalize_motivations(
                    meta, cluster.get("description", "")
                ),
                "target_sectors": normalize_sectors(meta),
                "target_regions": rollup_regions(victims),
                "target_countries": victims,
                "galaxy_aliases": galaxy_aliases,
                "references": [r for r in (meta.get("refs") or []) if r],
                "galaxy_uuid": cluster.get("uuid"),
                "galaxy_value": cluster_value,
            }

            # Galaxy synonyms extend the alias index too (GOLD SAHARA ->
            # G1024 even though ATT&CK doesn't list that name).
            for name in galaxy_aliases:
                key = normalize_alias(name)
                if key:
                    bucket = alias_to_gids.setdefault(key, [])
                    if gid not in bucket:
                        bucket.append(gid)

        if ambiguous:
            logger.warning(
                "MISP galaxy join: %d ambiguous matches skipped (add to "
                "AMBIGUITY_OVERRIDES to resolve):\n  %s",
                len(ambiguous), "\n  ".join(ambiguous),
            )

        self._contexts = contexts
        self._alias_to_gids = alias_to_gids
        logger.info(
            "MISP galaxy join: %d/%d ATT&CK groups enriched, %d ambiguous",
            len(contexts), len(groups), len(ambiguous),
        )

    # ── Accessors ──────────────────────────────────────────────────

    def get_context(self, gid: str) -> Optional[dict]:
        return self._contexts.get(gid.upper())

    def all_contexts(self) -> dict[str, dict]:
        return self._contexts

    def resolve_alias(self, name: str) -> list[str]:
        """G-IDs whose merged (ATT&CK + galaxy) alias set contains `name`."""
        return list(self._alias_to_gids.get(normalize_alias(name), []))

    def get_stats(self) -> dict:
        return {
            "clusters": len(self._clusters),
            "version": self._version,
            "enriched_groups": len(self._contexts),
            "loaded": self._loaded,
        }


actor_context_service = ActorContextService()


def merge_aliases(
    attack_aliases: list[str],
    context: Optional[dict],
    exclude: str = "",
) -> list[str]:
    """ATT&CK aliases + galaxy synonyms, deduped on normalized form,
    ATT&CK spelling preferred. `exclude` drops the actor's primary
    name (galaxy synonym lists usually repeat it)."""
    out: list[str] = []
    seen: set[str] = {normalize_alias(exclude)} if exclude else set()
    galaxy = (context or {}).get("galaxy_aliases") or []
    for name in list(attack_aliases) + galaxy:
        key = normalize_alias(name)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out
