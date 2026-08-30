"""Sigma / LOLRMM findings from the 2026-08-30 semantic review (issue #59)."""

from __future__ import annotations

from app.services.field_extractor import extract_sigma_fields


def _sigma(selection: dict, filt: dict | None = None):
    detection = {"selection": selection, "condition": "selection"}
    if filt:
        detection["filter"] = filt
        detection["condition"] = "selection and not filter"
    return extract_sigma_fields(detection)


def test_unix_binaries_reach_process_names():
    r = _sigma({"Image|endswith": ["/uname", "/hostname", "/openssl"], "a0|contains": "dd"})
    assert r.process_names == ["uname", "hostname", "openssl"]


def test_value_name_suffix_reaches_registry_keys():
    r = _sigma({"TargetObject|endswith": "\\IsCredGuardEnabled", "EventType": "SetValue"})
    assert r.registry_keys == ["\\IsCredGuardEnabled"]


def test_directory_fragment_is_a_process_path_not_a_name():
    r = _sigma({"Image|contains": ["\\AppData\\Local\\Temp\\", "\\Users\\Public\\"]})
    o = [o for o in r.observables if o.field == "Image"][0]
    assert (o.type, o.subtype) == ("process", "process_path")
    assert r.process_names == []


def test_ip_under_hostname_field_is_an_ip_address():
    r = _sigma({"DestinationHostname": "136.243.104.235"})
    o = [o for o in r.observables if o.field == "DestinationHostname"][0]
    assert (o.type, o.subtype) == ("network", "ip_address")
    assert r.network_indicators == ["136.243.104.235"]


def test_dotted_exe_names_keep_their_full_basename():
    r = _sigma({"Image|endswith": ["\\Syncro.Installer.exe", "\\Kabuto.App.Runner.exe"]})
    assert r.process_names == ["syncro.installer.exe", "kabuto.app.runner.exe"]


def test_filter_values_stay_off_the_surfaces():
    r = _sigma({"Image|endswith": "\\rundll32.exe"}, filt={"ParentImage|endswith": "\\msiexec.exe", "CommandLine|contains": "safe"})
    assert r.process_names == ["rundll32.exe"]
    negated = [o for o in r.observables if o.negated]
    assert {o.field for o in negated} == {"ParentImage", "CommandLine"}
