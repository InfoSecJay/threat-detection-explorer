"""Observable-level diff (#11): the pure matrix builder."""

from __future__ import annotations

from app.models.detection import Detection
from app.services.compare_diff import compute_observable_diff


def _rule(id_: str, source: str, observables: list[dict], **kw) -> Detection:
    base = dict(
        id=id_, source=source, source_file=f"{id_}.yml", source_repo_url="https://x",
        title=f"Rule {id_}", detection_logic="x", language="sigma", raw_content="raw",
        severity="high", status="stable", mitre_techniques=["T1218.011"], mitre_tactics=["TA0005"],
        platforms=["windows"], data_sources=["sysmon"], event_types=["process_creation"],
        extracted_observables=observables, extracted_fields_used=["Image"], quality_score=70,
    )
    base.update(kw)
    return Detection(**base)


SIGMA = _rule("a", "sigma", [
    {"field": "Image", "values": ["rundll32.exe", "regsvr32.exe"], "type": "process", "subtype": "process_name", "negated": False},
    {"field": "CommandLine", "values": ["javascript:"], "type": "process", "subtype": "command_line_pattern", "negated": False},
])
ELASTIC = _rule("b", "elastic", [
    {"field": "process.name", "values": ["Rundll32.exe"], "type": "process", "subtype": "process_name", "negated": False},
    {"field": "process.parent.name", "values": ["explorer.exe"], "type": "process", "subtype": "parent_process_name", "negated": True},
], language="eql", data_sources=["elastic_endpoint"], extracted_fields_used=["process.name", "process.parent.name"],
   mitre_techniques=["T1218.011", "T1218"])
SPLUNK = _rule("c", "splunk", [
    {"field": "Processes.process_name", "values": ["rundll32.exe"], "type": "process", "subtype": "process_name", "negated": False},
    {"field": "Processes.parent_process_name", "values": ["explorer.exe"], "type": "process", "subtype": "parent_process_name", "negated": False},
], language="spl", extracted_source_tables=["Endpoint.Processes"])


def test_values_compare_case_insensitively_and_keep_each_rules_field():
    d = compute_observable_diff([SIGMA, ELASTIC, SPLUNK])
    assert [r["id"] for r in d["rules"]] == ["a", "b", "c"]
    rundll = next(o for o in d["observables"] if o["value"] == "rundll32.exe")
    assert rundll["present_in"] == ["a", "b", "c"] and rundll["shared"] is True
    assert rundll["fields"] == {"a": ["Image"], "b": ["process.name"], "c": ["Processes.process_name"]}
    assert d["summary"]["shared_by_all"] == 1
    # regsvr32 and the command-line pattern are unique to sigma.
    assert d["summary"]["unique_by_rule"] == {"a": 2, "b": 0, "c": 0}


def test_exclusion_versus_match_is_a_contradiction():
    d = compute_observable_diff([ELASTIC, SPLUNK])
    parent = next(o for o in d["observables"] if o["value"] == "explorer.exe")
    assert parent["present_in"] == ["b", "c"] and parent["negated_in"] == ["b"]
    assert d["summary"]["contradictions"] == [{
        "type": "process", "subtype": "parent_process_name", "value": "explorer.exe",
        "matched_in": ["c"], "excluded_in": ["b"],
    }]


def test_axes_cover_metadata_and_shared_techniques():
    d = compute_observable_diff([SIGMA, ELASTIC])
    techniques = {a["value"]: a["present_in"] for a in d["axes"]["mitre_techniques"]}
    assert techniques == {"T1218.011": ["a", "b"], "T1218": ["b"]}
    assert d["summary"]["shared_techniques"] == ["T1218.011"]
    assert {a["value"] for a in d["axes"]["data_sources"]} == {"sysmon", "elastic_endpoint"}
    assert [a["value"] for a in d["axes"]["fields"]][0] == "Image"  # shared first, then alphabetical
    assert d["rules"][0]["observable_count"] == 3


def test_junk_observables_are_ignored():
    junk = _rule("j", "sigma", ["not-a-dict", {"field": "x", "values": None, "type": "weird"}, {"values": ["  "]}])
    d = compute_observable_diff([junk, SIGMA])
    assert d["summary"]["observables"] == 3
    assert d["summary"]["unique_by_rule"] == {"j": 0, "a": 3}
