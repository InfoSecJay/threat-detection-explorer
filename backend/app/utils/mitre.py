"""MITRE ATT&CK mapping utilities."""

# MITRE ATT&CK Tactic IDs and names
TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Reverse mapping: tactic name to ID
TACTIC_NAME_TO_ID = {v.lower().replace(" ", "_"): k for k, v in TACTICS.items()}


def get_tactic_name(tactic_id: str) -> str:
    """Get the human-readable name for a MITRE tactic ID.

    Args:
        tactic_id: MITRE tactic ID (e.g., "TA0001")

    Returns:
        Tactic name or the original ID if not found
    """
    return TACTICS.get(tactic_id.upper(), tactic_id)


def get_tactic_id(tactic_name: str) -> str | None:
    """Get the MITRE tactic ID for a tactic name.

    Args:
        tactic_name: Tactic name (e.g., "initial_access" or "Initial Access")

    Returns:
        Tactic ID or None if not found
    """
    normalized = tactic_name.lower().replace(" ", "_")
    return TACTIC_NAME_TO_ID.get(normalized)


def normalize_technique_id(technique: str) -> str:
    """Normalize a MITRE technique ID to standard format.

    Args:
        technique: Technique ID in various formats

    Returns:
        Normalized technique ID (e.g., "T1059.001")
    """
    # Remove any prefixes
    technique = technique.upper()
    if technique.startswith("ATTACK."):
        technique = technique[7:]

    # Ensure T prefix
    if not technique.startswith("T"):
        if technique.isdigit():
            technique = f"T{technique}"

    return technique


def is_subtechnique(technique_id: str) -> bool:
    """Check if a technique ID is a sub-technique.

    Args:
        technique_id: Technique ID to check

    Returns:
        True if this is a sub-technique (has . in ID)
    """
    return "." in technique_id


def get_parent_technique(subtechnique_id: str) -> str:
    """Get the parent technique ID for a sub-technique.

    Args:
        subtechnique_id: Sub-technique ID (e.g., "T1059.001")

    Returns:
        Parent technique ID (e.g., "T1059")
    """
    if "." in subtechnique_id:
        return subtechnique_id.split(".")[0]
    return subtechnique_id
