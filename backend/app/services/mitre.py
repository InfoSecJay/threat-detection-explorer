"""MITRE ATT&CK data service - fetches and caches data from official MITRE CTI repository."""

import json
import logging
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

from app.utils.datetime_utils import utcnow

logger = logging.getLogger(__name__)

# MITRE ATT&CK Enterprise data URL. attack-stix-data is MITRE's
# current official distribution (STIX 2.1) and — unlike the legacy
# mitre/cti bundle — carries an x-mitre-collection object with the
# release version, which Navigator layer exports pin to.
MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Mapping of deprecated/revoked technique IDs to their current equivalents
# This helps map old technique IDs in rules to current MITRE techniques
DEPRECATED_TECHNIQUE_MAPPING = {
    # Credential Access techniques that were reorganized
    "T1208": "T1558.003",  # Kerberoasting -> Steal or Forge Kerberos Tickets: Kerberoasting
    "T1003": "T1003",      # Credential Dumping (still exists but has sub-techniques now)
    "T1081": "T1552.001",  # Credentials in Files -> Unsecured Credentials: Credentials In Files
    "T1214": "T1552.002",  # Credentials in Registry -> Unsecured Credentials: Credentials in Registry
    "T1145": "T1552.004",  # Private Keys -> Unsecured Credentials: Private Keys
    "T1098": "T1098",      # Account Manipulation (still exists)

    # Discovery techniques
    "T1086": "T1059.001",  # PowerShell -> Command and Scripting Interpreter: PowerShell
    "T1064": "T1059",      # Scripting -> Command and Scripting Interpreter
    "T1117": "T1218.011",  # Regsvr32 -> Signed Binary Proxy Execution: Regsvr32
    "T1085": "T1218.011",  # Rundll32 -> Signed Binary Proxy Execution: Rundll32
    "T1118": "T1218.004",  # InstallUtil -> Signed Binary Proxy Execution: InstallUtil
    "T1121": "T1218.009",  # Regsvcs/Regasm -> Signed Binary Proxy Execution: Regsvcs/Regasm
    "T1127": "T1127",      # Trusted Developer Utilities (still exists)
    "T1170": "T1218.005",  # Mshta -> Signed Binary Proxy Execution: Mshta
    "T1191": "T1218.003",  # CMSTP -> Signed Binary Proxy Execution: CMSTP
    "T1028": "T1021.006",  # Windows Remote Management -> Remote Services: Windows Remote Management
    "T1100": "T1505.003",  # Web Shell -> Server Software Component: Web Shell
    "T1077": "T1021.002",  # Windows Admin Shares -> Remote Services: SMB/Windows Admin Shares
    "T1076": "T1021.001",  # Remote Desktop Protocol -> Remote Services: Remote Desktop Protocol

    # Persistence techniques
    "T1128": "T1546.011",  # Netsh Helper DLL -> Event Triggered Execution: Netsh Helper DLL
    "T1050": "T1543.003",  # New Service -> Create or Modify System Process: Windows Service
    "T1031": "T1543.003",  # Modify Existing Service -> Create or Modify System Process: Windows Service
    "T1060": "T1547.001",  # Registry Run Keys -> Boot or Logon Autostart Execution: Registry Run Keys
    "T1004": "T1547.004",  # Winlogon Helper DLL -> Boot or Logon Autostart Execution: Winlogon Helper DLL
    "T1058": "T1574.011",  # Service Registry Permissions Weakness -> Hijack Execution Flow
    "T1034": "T1574.007",  # Path Interception -> Hijack Execution Flow: Path Interception
    "T1038": "T1574.001",  # DLL Search Order Hijacking -> Hijack Execution Flow: DLL Search Order Hijacking
    "T1044": "T1574.010",  # File System Permissions Weakness -> Hijack Execution Flow

    # Defense Evasion
    "T1088": "T1548.002",  # Bypass UAC -> Abuse Elevation Control Mechanism: Bypass UAC
    "T1055": "T1055",      # Process Injection (still exists with sub-techniques)
    "T1108": "T1078",      # Redundant Access -> Valid Accounts
    "T1089": "T1562.001",  # Disabling Security Tools -> Impair Defenses: Disable or Modify Tools
    "T1116": "T1036.001",  # Code Signing -> Masquerading: Invalid Code Signature
    "T1107": "T1070.004",  # File Deletion -> Indicator Removal: File Deletion
    "T1066": "T1027",      # Indicator Removal from Tools -> Obfuscated Files or Information

    # Execution
    "T1035": "T1569.002",  # Service Execution -> System Services: Service Execution
    "T1053": "T1053",      # Scheduled Task (still exists with sub-techniques)

    # Exfiltration
    "T1002": "T1560",      # Data Compressed -> Archive Collected Data
    "T1022": "T1560.001",  # Data Encrypted -> Archive Collected Data: Archive via Utility
}

# Cache settings
CACHE_FILE = Path("data/mitre_attack.json")
CACHE_DURATION_HOURS = 24  # Refresh cache every 24 hours


class MitreAttackService:
    """Service for fetching and caching MITRE ATT&CK data."""

    def __init__(self):
        self._tactics: dict[str, dict] = {}
        self._techniques: dict[str, dict] = {}
        # ATT&CK Groups (`intrusion-set` STIX objects). Keyed by G-ID.
        # Each entry carries the same shape MITRE renders on
        # attack.mitre.org: name, aliases, description, references,
        # plus the derived `techniques` + `software` arrays populated
        # from `uses` relationships. See `_parse_mitre_data`.
        self._groups: dict[str, dict] = {}
        # ATT&CK Software (`malware` + `tool` STIX objects), keyed by
        # S-ID. Same shape as groups plus `type` (malware|tool) and
        # `groups` (reverse index of groups that use this software).
        self._software: dict[str, dict] = {}
        # ATT&CK content version actually ingested (x-mitre-collection
        # x_mitre_version, e.g. "17.1") — pinned into Navigator layer
        # exports instead of a hardcoded string.
        self._attack_version: Optional[str] = None
        # Kill-chain order of tactic ids from the Enterprise
        # x-mitre-matrix `tactic_refs`. ATT&CK adds tactics (v18 added
        # TA0112 Defense Impairment); a hardcoded order silently drops
        # the new column and every technique that lives only there.
        self._tactic_order: list[str] = []
        self._last_fetch: Optional[datetime] = None
        self._loaded = False

    async def ensure_loaded(self) -> None:
        """Ensure MITRE data is loaded, fetching if necessary."""
        if self._loaded and self._is_cache_valid():
            return

        # Try to load from cache first
        if self._load_from_cache():
            self._loaded = True
            return

        # Fetch fresh data
        await self.refresh()

    def _is_cache_valid(self) -> bool:
        """Check if the in-memory cache is still valid."""
        if self._last_fetch is None:
            return False
        return utcnow() - self._last_fetch < timedelta(hours=CACHE_DURATION_HOURS)

    def _load_from_cache(self) -> bool:
        """Load MITRE data from disk cache."""
        if not CACHE_FILE.exists():
            return False

        try:
            # Check file age
            file_mtime = datetime.fromtimestamp(CACHE_FILE.stat().st_mtime)
            if utcnow() - file_mtime > timedelta(hours=CACHE_DURATION_HOURS):
                logger.info("MITRE cache file is stale, will refresh")
                return False

            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            cached_tactics = data.get("tactics", {})
            cached_techniques = data.get("techniques", {})
            cached_groups = data.get("groups", {})
            cached_software = data.get("software", {})

            # Sanity check: reject caches produced by the old single-pass
            # parser that left every technique's `tactics` field empty.
            # Without this, a container that wrote the broken cache
            # within the last 24h would keep serving broken data even
            # after the parser fix ships. Sampling the first 20
            # techniques is enough — the bug was all-or-nothing.
            if cached_techniques:
                sample = list(cached_techniques.values())[:20]
                if not any(t.get("tactics") for t in sample):
                    logger.warning(
                        "MITRE cache appears broken (no techniques have tactics); "
                        "discarding and re-fetching."
                    )
                    return False

            # Second sanity check: pre-groups caches are missing the
            # groups + software payload. Discard and refetch so the
            # Threat Actors v2 rollout doesn't ship an empty catalog
            # from a stale container.
            if not cached_groups and not cached_software:
                logger.warning(
                    "MITRE cache predates Threat Actors v2 (no groups/software); "
                    "discarding and re-fetching."
                )
                return False

            # Third: caches written before the `modified` field shipped
            # would leave the table's last-modified column empty for up
            # to 24h. Discard and refetch once.
            if cached_groups and not any(
                g.get("modified") for g in list(cached_groups.values())[:20]
            ):
                logger.warning(
                    "MITRE cache predates group `modified` timestamps; "
                    "discarding and re-fetching."
                )
                return False

            self._tactics = cached_tactics
            self._techniques = cached_techniques
            self._groups = cached_groups
            self._software = cached_software
            self._attack_version = data.get("attack_version")
            self._tactic_order = [t for t in (data.get("tactic_order") or []) if t in cached_tactics]
            self._recompute_actor_weights()
            self._last_fetch = file_mtime
            logger.info(
                f"Loaded MITRE data from cache: {len(self._tactics)} tactics, "
                f"{len(self._techniques)} techniques, {len(self._groups)} groups, "
                f"{len(self._software)} software"
            )
            return True

        except Exception as e:
            logger.warning(f"Failed to load MITRE cache: {e}")
            return False

    def _save_to_cache(self) -> None:
        """Save MITRE data to disk cache."""
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "tactics": self._tactics,
                    "techniques": self._techniques,
                    "groups": self._groups,
                    "software": self._software,
                    "attack_version": self._attack_version,
                    "tactic_order": self._tactic_order,
                    "fetched_at": utcnow().isoformat(),
                }, f, indent=2)
            logger.info(f"Saved MITRE data to cache: {CACHE_FILE}")
        except Exception as e:
            logger.warning(f"Failed to save MITRE cache: {e}")

    async def refresh(self) -> bool:
        """Fetch fresh MITRE ATT&CK data from the official repository."""
        logger.info("Fetching MITRE ATT&CK data from official repository...")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(MITRE_CTI_URL)
                response.raise_for_status()
                mitre_data = response.json()

            self._parse_mitre_data(mitre_data)
            self._last_fetch = utcnow()
            self._loaded = True
            self._save_to_cache()

            logger.info(
                f"Fetched MITRE data: {len(self._tactics)} tactics, "
                f"{len(self._techniques)} techniques, {len(self._groups)} groups, "
                f"{len(self._software)} software"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to fetch MITRE ATT&CK data: {e}")
            # If we have stale cache, use it
            if self._tactics or self._techniques:
                logger.info("Using stale cache data")
                return False
            # Fall back to minimal hardcoded data
            self._load_fallback_data()
            return False

    def _parse_mitre_data(self, mitre_data: dict) -> None:
        """Parse MITRE STIX data into tactics and techniques mappings."""
        tactics = {}
        techniques = {}

        # Tactic ID to short name mapping (from x-mitre-tactic objects)
        tactic_id_map = {}  # Maps tactic x_mitre_shortname to tactic info

        # ── Two-pass: tactics before techniques ─────────────────────
        # Techniques reference tactics by short_name via
        # `kill_chain_phases`; we resolve short_name -> TA-ID through
        # `tactic_id_map`. A single-pass loop only works if every
        # `x-mitre-tactic` object appears BEFORE the `attack-pattern`
        # objects that reference it. Newer STIX bundles interleave the
        # two, which silently produces `technique.tactics=[]` for every
        # technique and empties out the coverage matrix. Two passes
        # make ordering irrelevant.
        objects = mitre_data.get("objects", [])

        # ATT&CK content version from the collection object.
        self._attack_version = None
        for obj in objects:
            if obj.get("type") == "x-mitre-collection":
                self._attack_version = obj.get("x_mitre_version")
                break

        # Matrix column order: x-mitre-matrix.tactic_refs lists tactic
        # STIX ids in kill-chain order; resolve them to TA ids below
        # once the tactic pass has run.
        matrix_refs: list[str] = []
        for obj in objects:
            if obj.get("type") == "x-mitre-matrix" and not obj.get("x_mitre_deprecated"):
                matrix_refs = list(obj.get("tactic_refs") or [])
                break
        stix_to_tactic: dict[str, str] = {}

        for obj in objects:
            if obj.get("type") != "x-mitre-tactic":
                continue
            tactic_name = obj.get("name", "")
            short_name = obj.get("x_mitre_shortname", "")
            tactic_id = None
            for ref in obj.get("external_references", []):
                ext_id = ref.get("external_id", "")
                if ext_id.startswith("TA"):
                    tactic_id = ext_id
                    break
            if tactic_id and tactic_name:
                tactics[tactic_id] = {
                    "id": tactic_id,
                    "name": tactic_name,
                    "short_name": short_name,
                    "description": obj.get("description", ""),
                    "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
                    "deprecated": obj.get("x_mitre_deprecated", False),
                }
                tactic_id_map[short_name] = tactic_id
                stix_to_tactic[obj.get("id", "")] = tactic_id

        self._tactic_order = [stix_to_tactic[r] for r in matrix_refs if r in stix_to_tactic]

        for obj in objects:
            obj_type = obj.get("type")

            # Parse techniques (tactics already fully loaded in pass 1)
            if obj_type == "attack-pattern":
                technique_id = None
                technique_url = None

                for ref in obj.get("external_references", []):
                    ext_id = ref.get("external_id", "")
                    if ext_id.startswith("T"):
                        technique_id = ext_id
                        technique_url = ref.get("url", f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}/")
                        break

                if technique_id:
                    # Get associated tactics
                    technique_tactics = []
                    for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                            phase_name = phase.get("phase_name", "")
                            if phase_name in tactic_id_map:
                                technique_tactics.append(tactic_id_map[phase_name])

                    # Extract richer metadata for the detail page — these
                    # come directly from the STIX object. Storing them
                    # lets the frontend render a proper "What is this
                    # technique?" card without a round-trip to
                    # attack.mitre.org.
                    raw_platforms = obj.get("x_mitre_platforms") or []
                    raw_data_sources = obj.get("x_mitre_data_sources") or []
                    parent_id = (
                        technique_id.split(".", 1)[0]
                        if "." in technique_id else None
                    )

                    techniques[technique_id] = {
                        "id": technique_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactics": technique_tactics,
                        "url": technique_url,
                        "deprecated": obj.get("x_mitre_deprecated", False),
                        "revoked": obj.get("revoked", False),
                        "is_subtechnique": "." in technique_id,
                        "parent_id": parent_id,
                        "platforms": raw_platforms,
                        "data_sources": raw_data_sources,
                        "detection": obj.get("x_mitre_detection", ""),
                        "version": obj.get("x_mitre_version"),
                    }

        # ── Threat Actors v2 passes ─────────────────────────────────
        # Groups (intrusion-set), Software (malware + tool), and the
        # `uses` relationships that connect them to each other and to
        # techniques. Requires the technique/tactic passes above to
        # have run first because we cross-reference back into them
        # when rendering associations.

        # Map STIX object IDs (uuid-ish) to their external ATT&CK ID
        # (G0016 / S0002 / T1059 / etc.). Relationships reference by
        # STIX ID; we resolve to external IDs for everything downstream.
        stix_to_ext: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") not in ("intrusion-set", "malware", "tool", "attack-pattern"):
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    if ext_id:
                        stix_to_ext[obj["id"]] = ext_id
                        break

        groups: dict[str, dict] = {}
        software: dict[str, dict] = {}

        for obj in objects:
            obj_type = obj.get("type")
            if obj.get("revoked"):
                continue

            if obj_type == "intrusion-set":
                ext_id = stix_to_ext.get(obj["id"])
                if not ext_id or not ext_id.startswith("G"):
                    continue
                # Aliases: intrusion-set uses `aliases` (which includes
                # the primary name); MITRE UI shows "Associated Groups"
                # from `aliases` minus name. Preserve full list.
                aliases = [a for a in (obj.get("aliases") or []) if a != obj.get("name")]
                groups[ext_id] = {
                    "id": ext_id,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "aliases": aliases,
                    "description": obj.get("description", ""),
                    "url": f"https://attack.mitre.org/groups/{ext_id}/",
                    "references": [
                        {"source_name": r.get("source_name", ""), "url": r.get("url", ""), "description": r.get("description", "")}
                        for r in obj.get("external_references", [])
                        if r.get("url") and r.get("source_name") != "mitre-attack"
                    ],
                    "deprecated": obj.get("x_mitre_deprecated", False),
                    "modified": obj.get("modified"),
                    # Filled in the relationship pass below.
                    "techniques": [],
                    "software": [],
                }

            elif obj_type in ("malware", "tool"):
                ext_id = stix_to_ext.get(obj["id"])
                if not ext_id or not ext_id.startswith("S"):
                    continue
                software[ext_id] = {
                    "id": ext_id,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "aliases": obj.get("x_mitre_aliases") or [],
                    "type": "malware" if obj_type == "malware" else "tool",
                    "description": obj.get("description", ""),
                    "url": f"https://attack.mitre.org/software/{ext_id}/",
                    "references": [
                        {"source_name": r.get("source_name", ""), "url": r.get("url", ""), "description": r.get("description", "")}
                        for r in obj.get("external_references", [])
                        if r.get("url") and r.get("source_name") != "mitre-attack"
                    ],
                    "deprecated": obj.get("x_mitre_deprecated", False),
                    "modified": obj.get("modified"),
                    "platforms": obj.get("x_mitre_platforms") or [],
                    # Filled in the relationship pass below.
                    "techniques": [],
                    "groups": [],
                }

        # Relationship pass — connect groups ↔ techniques, groups ↔
        # software, software ↔ techniques. Only `uses` relationships;
        # `attributed-to` / `revoked-by` etc. aren't needed for the
        # coverage view.
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("revoked"):
                continue
            if obj.get("relationship_type") != "uses":
                continue
            src = stix_to_ext.get(obj.get("source_ref", ""))
            tgt = stix_to_ext.get(obj.get("target_ref", ""))
            if not src or not tgt:
                continue

            # Group → technique
            if src.startswith("G") and tgt.startswith("T") and src in groups:
                groups[src]["techniques"].append(tgt)
            # Group → software (bidirectional link)
            elif src.startswith("G") and tgt.startswith("S"):
                if src in groups:
                    groups[src]["software"].append(tgt)
                if tgt in software:
                    software[tgt]["groups"].append(src)
            # Software → technique
            elif src.startswith("S") and tgt.startswith("T") and src in software:
                software[src]["techniques"].append(tgt)

        # Dedupe + sort so cache output is stable across refreshes.
        for g in groups.values():
            g["techniques"] = sorted(set(g["techniques"]))
            g["software"] = sorted(set(g["software"]))
        for s in software.values():
            s["techniques"] = sorted(set(s["techniques"]))
            s["groups"] = sorted(set(s["groups"]))

        self._tactics = tactics
        self._techniques = techniques
        self._groups = groups
        self._software = software
        self._recompute_actor_weights()

    def _recompute_actor_weights(self) -> None:
        """Derive per-technique distinctiveness weights from the
        actor -> technique matrix.

            n_t      = number of groups that use technique t
            weight_t = log(N / n_t)     (N = total group count)

        Techniques nearly every actor uses (T1059.001, T1078, ...)
        approach weight 0; techniques a handful use carry high weight.
        Techniques no actor uses are excluded from the corpus
        (`actor_weight` stays None) rather than dividing by zero.

        Derived purely from in-memory groups + techniques, so it runs
        after both a fresh STIX parse and a cache load — cache files
        written before this field existed heal themselves.
        """
        n = len(self._groups)
        if n == 0 or not self._techniques:
            return
        usage: dict[str, int] = {}
        for g in self._groups.values():
            for tid in g.get("techniques", []):
                usage[tid] = usage.get(tid, 0) + 1
        for tid, tech in self._techniques.items():
            n_t = usage.get(tid, 0)
            tech["actor_weight"] = math.log(n / n_t) if n_t > 0 else None

    def _load_fallback_data(self) -> None:
        """Load minimal fallback data if fetch fails and no cache exists."""
        logger.warning("Loading fallback MITRE data")
        self._tactics = {
            "TA0043": {"id": "TA0043", "name": "Reconnaissance", "short_name": "reconnaissance", "url": "https://attack.mitre.org/tactics/TA0043/", "deprecated": False},
            "TA0042": {"id": "TA0042", "name": "Resource Development", "short_name": "resource-development", "url": "https://attack.mitre.org/tactics/TA0042/", "deprecated": False},
            "TA0001": {"id": "TA0001", "name": "Initial Access", "short_name": "initial-access", "url": "https://attack.mitre.org/tactics/TA0001/", "deprecated": False},
            "TA0002": {"id": "TA0002", "name": "Execution", "short_name": "execution", "url": "https://attack.mitre.org/tactics/TA0002/", "deprecated": False},
            "TA0003": {"id": "TA0003", "name": "Persistence", "short_name": "persistence", "url": "https://attack.mitre.org/tactics/TA0003/", "deprecated": False},
            "TA0004": {"id": "TA0004", "name": "Privilege Escalation", "short_name": "privilege-escalation", "url": "https://attack.mitre.org/tactics/TA0004/", "deprecated": False},
            "TA0005": {"id": "TA0005", "name": "Defense Evasion", "short_name": "defense-evasion", "url": "https://attack.mitre.org/tactics/TA0005/", "deprecated": False},
            "TA0006": {"id": "TA0006", "name": "Credential Access", "short_name": "credential-access", "url": "https://attack.mitre.org/tactics/TA0006/", "deprecated": False},
            "TA0007": {"id": "TA0007", "name": "Discovery", "short_name": "discovery", "url": "https://attack.mitre.org/tactics/TA0007/", "deprecated": False},
            "TA0008": {"id": "TA0008", "name": "Lateral Movement", "short_name": "lateral-movement", "url": "https://attack.mitre.org/tactics/TA0008/", "deprecated": False},
            "TA0009": {"id": "TA0009", "name": "Collection", "short_name": "collection", "url": "https://attack.mitre.org/tactics/TA0009/", "deprecated": False},
            "TA0011": {"id": "TA0011", "name": "Command and Control", "short_name": "command-and-control", "url": "https://attack.mitre.org/tactics/TA0011/", "deprecated": False},
            "TA0010": {"id": "TA0010", "name": "Exfiltration", "short_name": "exfiltration", "url": "https://attack.mitre.org/tactics/TA0010/", "deprecated": False},
            "TA0040": {"id": "TA0040", "name": "Impact", "short_name": "impact", "url": "https://attack.mitre.org/tactics/TA0040/", "deprecated": False},
        }
        self._techniques = {}
        self._groups = {}
        self._software = {}
        self._loaded = True

    def get_tactic(self, tactic_id: str) -> Optional[dict]:
        """Get tactic info by ID."""
        return self._tactics.get(tactic_id)

    def get_technique(self, technique_id: str) -> Optional[dict]:
        """Get technique info by ID."""
        return self._techniques.get(technique_id)

    def get_tactic_name(self, tactic_id: str) -> str:
        """Get tactic name by ID, returns ID if not found."""
        tactic = self._tactics.get(tactic_id)
        return tactic["name"] if tactic else tactic_id

    def get_technique_name(self, technique_id: str) -> str:
        """Get technique name by ID, returns ID if not found."""
        technique = self._techniques.get(technique_id)
        return technique["name"] if technique else technique_id

    def get_all_tactics(self) -> dict[str, dict]:
        """Get all tactics."""
        return self._tactics

    # Kill-chain order as of ATT&CK v17; only the fallback when the
    # cache predates matrix-order parsing. Any live tactic missing from
    # it is appended, so a new tactic is never dropped again.
    _LEGACY_TACTIC_ORDER = [
        "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
        "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
    ]

    def get_tactic_order(self) -> list[str]:
        """Non-deprecated tactic ids in matrix (kill-chain) order."""
        order = list(self._tactic_order) or list(self._LEGACY_TACTIC_ORDER)
        for tid in self._tactics:
            if tid not in order:
                order.append(tid)
        return [t for t in order if t in self._tactics and not self._tactics[t].get("deprecated")]

    def get_all_techniques(self) -> dict[str, dict]:
        """Get all techniques."""
        return self._techniques

    # ── Threat Actors v2 accessors ─────────────────────────────────
    def get_all_groups(self) -> dict[str, dict]:
        """All non-revoked ATT&CK Groups keyed by G-ID."""
        return self._groups

    def get_group(self, group_id: str) -> Optional[dict]:
        """Get a single group by G-ID."""
        return self._groups.get(group_id.upper())

    def get_all_software(self) -> dict[str, dict]:
        """All non-revoked ATT&CK Software (malware + tools) keyed by S-ID."""
        return self._software

    def get_software(self, software_id: str) -> Optional[dict]:
        """Get a single software entry by S-ID."""
        return self._software.get(software_id.upper())

    def get_attack_version(self) -> Optional[str]:
        """ATT&CK content version actually ingested (e.g. '17.1')."""
        return self._attack_version

    def get_stats(self) -> dict:
        """Get stats about loaded MITRE data."""
        return {
            "attack_version": self._attack_version,
            "tactics_count": len(self._tactics),
            "techniques_count": len(self._techniques),
            "subtechniques_count": sum(1 for t in self._techniques.values() if t.get("is_subtechnique")),
            "groups_count": len(self._groups),
            "software_count": len(self._software),
            "malware_count": sum(1 for s in self._software.values() if s.get("type") == "malware"),
            "tool_count": sum(1 for s in self._software.values() if s.get("type") == "tool"),
            "last_fetch": self._last_fetch.isoformat() if self._last_fetch else None,
            "loaded": self._loaded,
        }

    def is_valid_technique(self, technique_id: str) -> bool:
        """Check if a technique ID is valid and not deprecated/revoked."""
        technique = self._techniques.get(technique_id)
        if not technique:
            return False
        return not technique.get("deprecated", False) and not technique.get("revoked", False)

    def map_technique(self, technique_id: str) -> Optional[str]:
        """Map a technique ID to its current equivalent.

        Returns the mapped technique ID if deprecated/revoked,
        the original ID if valid, or None if invalid and unmapped.
        """
        # Check if it's already a valid technique
        if self.is_valid_technique(technique_id):
            return technique_id

        # Check deprecation mapping
        if technique_id in DEPRECATED_TECHNIQUE_MAPPING:
            mapped_id = DEPRECATED_TECHNIQUE_MAPPING[technique_id]
            # Verify the mapped technique is valid
            if self.is_valid_technique(mapped_id):
                return mapped_id

        # Check if it exists but is deprecated - try to use it anyway
        if technique_id in self._techniques:
            return technique_id

        return None

    def get_valid_techniques(self) -> dict[str, dict]:
        """Get all valid (non-deprecated, non-revoked) techniques."""
        return {
            tid: tinfo for tid, tinfo in self._techniques.items()
            if not tinfo.get("deprecated", False) and not tinfo.get("revoked", False)
        }

    def get_tactics_for_techniques(self, technique_ids: list[str]) -> list[str]:
        """Get all tactics associated with a list of techniques.

        Args:
            technique_ids: List of technique IDs (e.g., ['T1078', 'T1078.004'])

        Returns:
            Deduplicated list of tactic IDs (e.g., ['TA0001', 'TA0003', 'TA0004'])
        """
        # Ensure data is loaded (sync version - tries cache only)
        if not self._loaded:
            self._load_from_cache()

        tactics = set()

        for tech_id in technique_ids:
            # Try to map deprecated techniques first
            mapped_id = self.map_technique(tech_id)
            if mapped_id:
                tech_id = mapped_id

            technique = self._techniques.get(tech_id)
            if technique:
                for tactic_id in technique.get("tactics", []):
                    tactics.add(tactic_id)

            # For sub-techniques, also check parent technique
            if "." in tech_id:
                parent_id = tech_id.split(".")[0]
                parent = self._techniques.get(parent_id)
                if parent:
                    for tactic_id in parent.get("tactics", []):
                        tactics.add(tactic_id)

        return sorted(tactics)


# Global singleton instance
mitre_service = MitreAttackService()
