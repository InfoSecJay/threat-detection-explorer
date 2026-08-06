"""MITRE ATT&CK Group + Software display-name resolution.

The parsers preserve the raw G-ID / S-ID from vendor tags. This module
turns those into human-readable display names for the UI, plus known
aliases so search matches the way users actually spell things
("Cozy Bear" -> G0016).

The table is a curated subset of high-frequency IDs that appear in the
Sigma + LOLRMM corpora. Missing IDs fall through to their raw ID as
the display name — the UI still renders something meaningful even
before the table is expanded.

To refresh from the canonical source:
  https://github.com/mitre-attack/attack-stix-data
Look for `intrusion-set` (Groups) and `malware` / `tool` (Software).
"""


# ── Groups (Intrusion Sets) ──────────────────────────────────────────
# Keyed by G-ID. `aliases` is any additional name the group is called
# in the wild — helps with cross-vendor matching later.
GROUPS: dict[str, dict] = {
    "G0007": {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Sednit"]},
    "G0010": {"name": "Turla", "aliases": ["Snake", "Uroburos", "Venomous Bear"]},
    "G0016": {"name": "APT29", "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard"]},
    "G0032": {"name": "Lazarus Group", "aliases": ["Hidden Cobra", "Zinc"]},
    "G0035": {"name": "Dragonfly", "aliases": ["Energetic Bear", "Berserk Bear"]},
    "G0037": {"name": "FIN6", "aliases": ["Skeleton Spider"]},
    "G0045": {"name": "menuPass", "aliases": ["APT10", "Stone Panda"]},
    "G0046": {"name": "FIN7", "aliases": ["Carbon Spider"]},
    "G0049": {"name": "OilRig", "aliases": ["APT34", "Helix Kitten"]},
    "G0050": {"name": "APT32", "aliases": ["OceanLotus", "SeaLotus"]},
    "G0059": {"name": "Magic Hound", "aliases": ["APT35", "Charming Kitten", "Cobalt Illusion"]},
    "G0064": {"name": "APT33", "aliases": ["Elfin", "Refined Kitten"]},
    "G0065": {"name": "Leviathan", "aliases": ["APT40", "TEMP.Periscope"]},
    "G0069": {"name": "MuddyWater", "aliases": ["Static Kitten", "Mercury"]},
    "G0074": {"name": "Dragonfly 2.0", "aliases": []},
    "G0075": {"name": "Rancor", "aliases": []},
    "G0080": {"name": "Cobalt Group", "aliases": ["Gold Kingswood"]},
    "G0087": {"name": "APT39", "aliases": ["Chafer", "Remix Kitten"]},
    "G0088": {"name": "TEMP.Veles", "aliases": ["XENOTIME"]},
    "G0091": {"name": "Silence", "aliases": ["Whisper Spider"]},
    "G0092": {"name": "TA505", "aliases": ["Hive0065", "Graceful Spider"]},
    "G0096": {"name": "APT41", "aliases": ["Wicked Panda", "BARIUM"]},
    "G0099": {"name": "APT-C-36", "aliases": ["Blind Eagle"]},
    "G0102": {"name": "Wizard Spider", "aliases": ["Trickbot", "UNC1878", "Grim Spider"]},
    "G0106": {"name": "Rocke", "aliases": []},
    "G0114": {"name": "Chimera", "aliases": []},
    "G0115": {"name": "GOLD SOUTHFIELD", "aliases": ["REvil crew"]},
    "G0119": {"name": "Indrik Spider", "aliases": ["Evil Corp"]},
    "G0125": {"name": "HAFNIUM", "aliases": []},
    "G0128": {"name": "ZIRCONIUM", "aliases": ["APT31"]},
    "G0130": {"name": "Ajax Security Team", "aliases": ["Rocket Kitten"]},
    "G0132": {"name": "BlackTech", "aliases": ["Circuit Panda"]},
    "G0134": {"name": "Transparent Tribe", "aliases": ["APT36", "COPPER FIELDSTONE"]},
    "G0138": {"name": "Andariel", "aliases": ["Silent Chollima"]},
    "G0140": {"name": "LazyScripter", "aliases": []},
    "G0142": {"name": "Confucius", "aliases": []},
    "G0143": {"name": "Aoqin Dragon", "aliases": []},
    "G0146": {"name": "FIN13", "aliases": ["Elephant Beetle"]},
    "G1004": {"name": "LAPSUS$", "aliases": ["Strawberry Tempest", "DEV-0537"]},
    "G1006": {"name": "Earth Lusca", "aliases": ["TAG-22"]},
    "G1015": {"name": "Scattered Spider", "aliases": ["Octo Tempest", "0ktapus", "UNC3944"]},
    "G1017": {"name": "Volt Typhoon", "aliases": ["Vanguard Panda", "BRONZE SILHOUETTE"]},
    "G1018": {"name": "TA2541", "aliases": []},
    "G1023": {"name": "APT5", "aliases": ["Keyhole Panda", "UNC2630"]},
    "G1027": {"name": "Genesis Market", "aliases": []},
    "G1030": {"name": "Agrius", "aliases": ["Pink Sandstorm", "Agonizing Serpens"]},
    "G1032": {"name": "INC Ransom", "aliases": []},
    "G1035": {"name": "Winter Vivern", "aliases": ["TA473"]},
    "G1039": {"name": "Salt Typhoon", "aliases": ["GhostEmperor", "UNC5807"]},
    "G1040": {"name": "Play", "aliases": ["PlayCrypt"]},
    "G1044": {"name": "APT44", "aliases": ["Sandworm Team", "Voodoo Bear"]},
    "G1046": {"name": "Storm-1811", "aliases": ["Storm 1811"]},
}


# ── Software (Malware + Tools) ───────────────────────────────────────
SOFTWARE: dict[str, dict] = {
    "S0002": {"name": "Mimikatz", "type": "tool"},
    "S0029": {"name": "PsExec", "type": "tool"},
    "S0039": {"name": "Net", "type": "tool"},
    "S0057": {"name": "Tasklist", "type": "tool"},
    "S0075": {"name": "Reg", "type": "tool"},
    "S0089": {"name": "BlackEnergy", "type": "malware"},
    "S0096": {"name": "Systeminfo", "type": "tool"},
    "S0106": {"name": "cmd", "type": "tool"},
    "S0154": {"name": "Cobalt Strike", "type": "tool"},
    "S0160": {"name": "certutil", "type": "tool"},
    "S0194": {"name": "PowerSploit", "type": "tool"},
    "S0266": {"name": "TrickBot", "type": "malware"},
    "S0357": {"name": "Impacket", "type": "tool"},
    "S0363": {"name": "Empire", "type": "tool"},
    "S0367": {"name": "Emotet", "type": "malware"},
    "S0378": {"name": "PoshC2", "type": "tool"},
    "S0384": {"name": "Dridex", "type": "malware"},
    "S0385": {"name": "njRAT", "type": "malware"},
    "S0397": {"name": "LoJax", "type": "malware"},
    "S0432": {"name": "Bundlore", "type": "malware"},
    "S0446": {"name": "Ryuk", "type": "malware"},
    "S0450": {"name": "Hancitor", "type": "malware"},
    "S0454": {"name": "Cadelspy", "type": "malware"},
    "S0458": {"name": "Ramsay", "type": "malware"},
    "S0468": {"name": "Black Basta", "type": "malware"},
    "S0496": {"name": "REvil", "type": "malware"},
    "S0521": {"name": "BloodHound", "type": "tool"},
    "S0552": {"name": "AdFind", "type": "tool"},
    "S0554": {"name": "Egregor", "type": "malware"},
    "S0575": {"name": "Conti", "type": "malware"},
    "S0605": {"name": "EKANS", "type": "malware"},
    "S0623": {"name": "Xbash", "type": "malware"},
    "S0629": {"name": "Rclone", "type": "tool"},
    "S0640": {"name": "Avaddon", "type": "malware"},
    "S0645": {"name": "Wevtutil", "type": "tool"},
    "S0648": {"name": "GoldFinder", "type": "malware"},
    "S0650": {"name": "QakBot", "type": "malware"},
    "S0658": {"name": "XCSSET", "type": "malware"},
    "S0670": {"name": "WarzoneRAT", "type": "malware"},
    "S1053": {"name": "AvosLocker", "type": "malware"},
    "S1058": {"name": "Prestige", "type": "malware"},
    "S1068": {"name": "BlackCat", "type": "malware"},
    "S1088": {"name": "AsyncRAT", "type": "malware"},
    "S1091": {"name": "IcedID", "type": "malware"},
    "S1099": {"name": "Samurai", "type": "malware"},
    "S1105": {"name": "COATHANGER", "type": "malware"},
    "S1114": {"name": "SnappyBee", "type": "malware"},
    "S1141": {"name": "LockBit", "type": "malware"},
}


def resolve_group(gid: str) -> dict:
    """Return {id, name, aliases} for a G-ID, falling back to raw ID as name."""
    entry = GROUPS.get(gid.upper())
    if entry:
        return {"id": gid.upper(), "name": entry["name"], "aliases": entry["aliases"]}
    return {"id": gid.upper(), "name": gid.upper(), "aliases": []}


def resolve_software(sid: str) -> dict:
    """Return {id, name, type} for an S-ID, falling back to raw ID as name."""
    entry = SOFTWARE.get(sid.upper())
    if entry:
        return {"id": sid.upper(), "name": entry["name"], "type": entry["type"]}
    return {"id": sid.upper(), "name": sid.upper(), "type": "unknown"}
