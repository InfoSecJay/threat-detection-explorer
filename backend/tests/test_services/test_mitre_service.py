"""Tests for the MITRE ATT&CK service's STIX parsing.

Pins the Threat Actors v2 parser passes: `intrusion-set` -> groups,
`malware`/`tool` -> software, and `uses` relationships that link
groups <-> techniques + groups <-> software + software <-> techniques.

The bundle used here is hand-crafted to be minimal but shaped exactly
like a slice of the real MITRE STIX file — same object types, same
`external_references` structure, same relationship shape.
"""

import pytest

from app.services.mitre import MitreAttackService


def _bundle() -> dict:
    """A minimal STIX bundle: 1 tactic, 2 techniques, 1 group, 1 malware,
    1 tool, and the `uses` relationships wiring them together."""
    return {
        "objects": [
            # Tactic
            {
                "id": "x-mitre-tactic--exec-uuid",
                "type": "x-mitre-tactic",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "description": "run stuff",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "TA0002"},
                ],
            },
            # Techniques
            {
                "id": "attack-pattern--t1059-uuid",
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059", "url": "https://attack.mitre.org/techniques/T1059/"},
                ],
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Command: Command Execution"],
                "description": "adversaries run commands",
            },
            {
                "id": "attack-pattern--t1055-uuid",
                "type": "attack-pattern",
                "name": "Process Injection",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1055", "url": "https://attack.mitre.org/techniques/T1055/"},
                ],
                "description": "inject code",
            },
            # Intrusion set (Group)
            {
                "id": "intrusion-set--apt29-uuid",
                "type": "intrusion-set",
                "name": "APT29",
                "aliases": ["APT29", "Cozy Bear", "Nobelium"],
                "description": "APT29 is a Russian state actor.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016", "url": "https://attack.mitre.org/groups/G0016/"},
                    {"source_name": "Mandiant APT29", "url": "https://mandiant.example/apt29", "description": "background"},
                ],
            },
            # Malware
            {
                "id": "malware--mimikatz-uuid",
                "type": "malware",
                "name": "Mimikatz",
                "x_mitre_aliases": ["Mimikatz"],
                "x_mitre_platforms": ["Windows"],
                "description": "credential dumping tool",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0002", "url": "https://attack.mitre.org/software/S0002/"},
                ],
            },
            # Tool
            {
                "id": "tool--cobaltstrike-uuid",
                "type": "tool",
                "name": "Cobalt Strike",
                "x_mitre_aliases": ["Cobalt Strike"],
                "description": "commercial adversary simulation",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0154", "url": "https://attack.mitre.org/software/S0154/"},
                ],
            },
            # Relationships: APT29 uses T1059, T1055, Mimikatz, Cobalt Strike;
            # Mimikatz uses T1059; Cobalt Strike uses T1055.
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "intrusion-set--apt29-uuid", "target_ref": "attack-pattern--t1059-uuid",
             "id": "relationship--r1"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "intrusion-set--apt29-uuid", "target_ref": "attack-pattern--t1055-uuid",
             "id": "relationship--r2"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "intrusion-set--apt29-uuid", "target_ref": "malware--mimikatz-uuid",
             "id": "relationship--r3"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "intrusion-set--apt29-uuid", "target_ref": "tool--cobaltstrike-uuid",
             "id": "relationship--r4"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "malware--mimikatz-uuid", "target_ref": "attack-pattern--t1059-uuid",
             "id": "relationship--r5"},
            {"type": "relationship", "relationship_type": "uses",
             "source_ref": "tool--cobaltstrike-uuid", "target_ref": "attack-pattern--t1055-uuid",
             "id": "relationship--r6"},
        ]
    }


class TestGroupParsing:
    def setup_method(self):
        self.svc = MitreAttackService()
        self.svc._parse_mitre_data(_bundle())

    def test_group_parsed_with_metadata(self):
        g = self.svc.get_group("G0016")
        assert g is not None
        assert g["name"] == "APT29"
        assert "Cozy Bear" in g["aliases"]
        assert "Nobelium" in g["aliases"]
        # Primary name excluded from aliases (MITRE UI convention).
        assert "APT29" not in g["aliases"]
        assert g["description"].startswith("APT29 is")
        assert g["url"] == "https://attack.mitre.org/groups/G0016/"

    def test_group_external_references_excludes_mitre_selfref(self):
        g = self.svc.get_group("G0016")
        # `mitre-attack` self-reference is excluded from references
        # (it's already captured as `url`); external refs remain.
        assert all(r["source_name"] != "mitre-attack" for r in g["references"])
        assert any("mandiant.example" in r["url"] for r in g["references"])

    def test_group_techniques_from_relationships(self):
        g = self.svc.get_group("G0016")
        assert set(g["techniques"]) == {"T1059", "T1055"}

    def test_group_software_from_relationships(self):
        g = self.svc.get_group("G0016")
        assert set(g["software"]) == {"S0002", "S0154"}

    def test_case_insensitive_lookup(self):
        assert self.svc.get_group("g0016") is not None


class TestSoftwareParsing:
    def setup_method(self):
        self.svc = MitreAttackService()
        self.svc._parse_mitre_data(_bundle())

    def test_malware_parsed_with_type(self):
        s = self.svc.get_software("S0002")
        assert s is not None
        assert s["name"] == "Mimikatz"
        assert s["type"] == "malware"
        assert "Windows" in s["platforms"]

    def test_tool_parsed_with_type(self):
        s = self.svc.get_software("S0154")
        assert s is not None
        assert s["type"] == "tool"

    def test_software_techniques_from_relationships(self):
        assert self.svc.get_software("S0002")["techniques"] == ["T1059"]
        assert self.svc.get_software("S0154")["techniques"] == ["T1055"]

    def test_software_groups_reverse_index(self):
        assert self.svc.get_software("S0002")["groups"] == ["G0016"]
        assert self.svc.get_software("S0154")["groups"] == ["G0016"]


class TestBulkAccessors:
    def setup_method(self):
        self.svc = MitreAttackService()
        self.svc._parse_mitre_data(_bundle())

    def test_get_all_groups(self):
        groups = self.svc.get_all_groups()
        assert isinstance(groups, dict)
        assert "G0016" in groups

    def test_get_all_software_includes_both_types(self):
        sw = self.svc.get_all_software()
        assert "S0002" in sw and "S0154" in sw

    def test_stats_reports_new_counts(self):
        stats = self.svc.get_stats()
        assert stats["groups_count"] == 1
        assert stats["software_count"] == 2
        assert stats["malware_count"] == 1
        assert stats["tool_count"] == 1


class TestRelationshipEdgeCases:
    def test_revoked_relationship_ignored(self):
        bundle = _bundle()
        # Add a revoked "uses T1055" — should NOT show up on the group.
        bundle["objects"].append({
            "type": "relationship", "relationship_type": "uses", "revoked": True,
            "source_ref": "intrusion-set--apt29-uuid",
            "target_ref": "attack-pattern--never-happens-uuid",
            "id": "relationship--revoked",
        })
        svc = MitreAttackService()
        svc._parse_mitre_data(bundle)
        # Neither the technique existed nor the relationship should
        # add it — same net effect. But specifically the group's
        # techniques stay the same as the base.
        assert set(svc.get_group("G0016")["techniques"]) == {"T1059", "T1055"}

    def test_non_uses_relationship_ignored(self):
        bundle = _bundle()
        # `attributed-to` shouldn't populate techniques.
        bundle["objects"].append({
            "type": "relationship", "relationship_type": "attributed-to",
            "source_ref": "intrusion-set--apt29-uuid",
            "target_ref": "attack-pattern--t1055-uuid",
            "id": "relationship--attributed",
        })
        svc = MitreAttackService()
        svc._parse_mitre_data(bundle)
        # Techniques still just from `uses` relationships.
        assert set(svc.get_group("G0016")["techniques"]) == {"T1059", "T1055"}

    def test_revoked_group_omitted(self):
        bundle = _bundle()
        for obj in bundle["objects"]:
            if obj.get("id") == "intrusion-set--apt29-uuid":
                obj["revoked"] = True
        svc = MitreAttackService()
        svc._parse_mitre_data(bundle)
        assert svc.get_group("G0016") is None
