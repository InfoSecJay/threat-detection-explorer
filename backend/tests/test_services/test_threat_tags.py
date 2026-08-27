"""Tests for vendor threat-tag classification (issue #20).

Sentinel tags mix bare actor codenames (NOBELIUM, DEV-0537, Zinc) with
compliance frameworks and table names. Pinned against the real tag
vocabulary observed in the Sentinel repo scan (2026-08-26): 16 threat
tags, 129 plain tags, zero false classifications.
"""

from app.services.threat_tags import (
    ACTOR_CODE_RE,
    threat_reference_tags,
)

# Injected registries — classification semantics only, no service load.
GROUPS = {
    "nobelium": ["G0016"],
    "zinc": ["G0032", "G1036"],
    "aquablizzard": ["G0047"],
    "mercury": ["G0069"],
}
SOFTWARE = {
    "solorigate": "S0559",
    "sunburst": "S0559",
    "qakbot": "S0650",
    "psexec": "S0029",
}


def _classify(tags):
    return threat_reference_tags(
        tags,
        resolve_group=lambda t: GROUPS.get(t.lower().replace(" ", ""), []),
        software_index=SOFTWARE,
    )


def test_group_aliases_classify():
    assert _classify(["NOBELIUM", "Zinc", "Aqua Blizzard", "Mercury"]) == [
        "NOBELIUM", "Zinc", "Aqua Blizzard", "Mercury",
    ]


def test_software_aliases_classify():
    # Solorigate is SUNBURST's (S0559) alias — the group registry alone
    # misses it, the software catalog catches it.
    assert _classify(["Solorigate", "Qakbot", "PsExec"]) == [
        "Solorigate", "Qakbot", "PsExec",
    ]


def test_tracking_codes_classify_without_registry():
    # Microsoft rotates DEV-#### faster than any registry tracks.
    assert _classify(["DEV-0537", "Dev-0270", "Storm-0558", "UNC2452",
                      "APT29", "FIN7", "TA505"]) == [
        "DEV-0537", "Dev-0270", "Storm-0558", "UNC2452",
        "APT29", "FIN7", "TA505",
    ]


def test_attck_tactic_ids_are_not_proofpoint_actors():
    # TA0001..TA0043 are ATT&CK tactic IDs, not TA-number actors.
    assert not ACTOR_CODE_RE.match("TA0001")
    assert not ACTOR_CODE_RE.match("TA0040")
    assert ACTOR_CODE_RE.match("TA505")
    assert ACTOR_CODE_RE.match("TA4557")


def test_framework_cve_and_table_tags_stay_plain():
    # The real Sentinel tag vocabulary that must NOT classify.
    assert _classify([
        "NIST 800-53 r5",
        "CIS AWS Foundations Benchmark v1.4.0",
        "PCI DSS v3.2.1",
        "CVE-2021-44228",
        "Log4j",
        "log4shell",
        "SigninLogs",
        "AzureActivity",
        "SQL",
        "Ransomware",
        "SimuLand",
        "Fusion",
        "Defense Evasion",
    ]) == []


def test_verbatim_dedupe_and_junk_tolerance():
    got = _classify(["  NOBELIUM  ", "NOBELIUM", None, 42, "", "Qakbot"])
    assert got == ["NOBELIUM", "Qakbot"]
    assert _classify([]) == []
    assert _classify(None) == []
