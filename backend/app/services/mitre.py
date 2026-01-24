"""MITRE ATT&CK data service - fetches and caches data from official MITRE CTI repository."""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# MITRE ATT&CK Enterprise data URL
MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Cache settings
CACHE_FILE = Path("data/mitre_attack.json")
CACHE_DURATION_HOURS = 24  # Refresh cache every 24 hours


class MitreAttackService:
    """Service for fetching and caching MITRE ATT&CK data."""

    def __init__(self):
        self._tactics: dict[str, dict] = {}
        self._techniques: dict[str, dict] = {}
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
        return datetime.utcnow() - self._last_fetch < timedelta(hours=CACHE_DURATION_HOURS)

    def _load_from_cache(self) -> bool:
        """Load MITRE data from disk cache."""
        if not CACHE_FILE.exists():
            return False

        try:
            # Check file age
            file_mtime = datetime.fromtimestamp(CACHE_FILE.stat().st_mtime)
            if datetime.utcnow() - file_mtime > timedelta(hours=CACHE_DURATION_HOURS):
                logger.info("MITRE cache file is stale, will refresh")
                return False

            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._tactics = data.get("tactics", {})
            self._techniques = data.get("techniques", {})
            self._last_fetch = file_mtime
            logger.info(f"Loaded MITRE data from cache: {len(self._tactics)} tactics, {len(self._techniques)} techniques")
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
                    "fetched_at": datetime.utcnow().isoformat(),
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
            self._last_fetch = datetime.utcnow()
            self._loaded = True
            self._save_to_cache()

            logger.info(f"Fetched MITRE data: {len(self._tactics)} tactics, {len(self._techniques)} techniques")
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

        for obj in mitre_data.get("objects", []):
            obj_type = obj.get("type")

            # Parse tactics
            if obj_type == "x-mitre-tactic":
                tactic_name = obj.get("name", "")
                short_name = obj.get("x_mitre_shortname", "")

                # Extract tactic ID from external references
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
                        "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
                        "deprecated": obj.get("x_mitre_deprecated", False),
                    }
                    tactic_id_map[short_name] = tactic_id

            # Parse techniques
            elif obj_type == "attack-pattern":
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

                    techniques[technique_id] = {
                        "id": technique_id,
                        "name": obj.get("name", ""),
                        "tactics": technique_tactics,
                        "url": technique_url,
                        "deprecated": obj.get("x_mitre_deprecated", False),
                        "is_subtechnique": "." in technique_id,
                    }

        self._tactics = tactics
        self._techniques = techniques

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

    def get_all_techniques(self) -> dict[str, dict]:
        """Get all techniques."""
        return self._techniques

    def get_stats(self) -> dict:
        """Get stats about loaded MITRE data."""
        return {
            "tactics_count": len(self._tactics),
            "techniques_count": len(self._techniques),
            "subtechniques_count": sum(1 for t in self._techniques.values() if t.get("is_subtechnique")),
            "last_fetch": self._last_fetch.isoformat() if self._last_fetch else None,
            "loaded": self._loaded,
        }


# Global singleton instance
mitre_service = MitreAttackService()
