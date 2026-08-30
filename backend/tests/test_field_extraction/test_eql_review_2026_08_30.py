"""EQL findings from the 2026-08-30 semantic review (issue #59).

Tuple values were never read (`process.name : ("a", "b")` yielded
nothing, 13/28 sampled EQL rules), and only `!=` set negation, so
`not (...)` exclusion blocks landed on the surfaces as things the rule
detects. Fixtures below are the shapes seen in production.
"""

from __future__ import annotations

from app.services.field_extractor import _extract_exe_names, extract_elastic_fields


def _obs(result, field):
    return [o for o in result.observables if o.field == field]


def test_colon_tuple_values_are_read_with_optional_field_prefix():
    r = extract_elastic_fields(
        'process where process.name : ("cmd.exe", "powershell.exe",\n  "pwsh.exe") and ?dll.name : ("wlbsctrl.dll", "wbemcomn.dll")',
        language="eql",
    )
    assert _obs(r, "process.name")[0].values == ["cmd.exe", "powershell.exe", "pwsh.exe"]
    assert _obs(r, "dll.name")[0].values == ["wlbsctrl.dll", "wbemcomn.dll"]
    assert r.process_names == ["cmd.exe", "powershell.exe", "pwsh.exe"]


def test_exclusion_blocks_are_negated_and_stay_off_surfaces():
    r = extract_elastic_fields(
        'process where process.name : "bash" and not (process.parent.name : "sudo" or process.args : "x") '
        'and not user.id : "S-1-5-18" and not process.hash.sha256 in ("aa", "bb")',
        language="eql",
    )
    assert _obs(r, "process.name")[0].negated is False
    assert _obs(r, "process.parent.name")[0].negated is True
    assert _obs(r, "process.args")[0].negated is True
    assert _obs(r, "user.id")[0].negated is True
    assert _obs(r, "process.hash.sha256")[0].negated is True
    assert r.process_names == ["bash"]


def test_not_in_and_double_negation():
    r = extract_elastic_fields(
        'process where process.name != "a.exe" and not (process.name != "b.exe") and process.parent.name not in ("c.exe")',
        language="eql",
    )
    by = {o.values[0]: o.negated for o in r.observables if o.field in ("process.name", "process.parent.name")}
    assert by == {"a.exe": True, "b.exe": False, "c.exe": True}
    assert r.process_names == ["b.exe"]


def test_like_regex_in_and_numbers():
    r = extract_elastic_fields(
        'file where file.extension in ("dll", "cpl") and file.path like~ ("C:\\\\Windows\\\\*", "D:\\\\x\\\\*") '
        'and process.pid == 4 and process.args regex~ "-c.*" and dll.Ext.device.product_id : ("Virtual DVD-ROM", "Virtual Disk")',
        language="eql",
    )
    assert _obs(r, "file.extension")[0].values == ["dll", "cpl"]
    assert _obs(r, "file.path")[0].values == ["C:\\\\Windows\\\\*", "D:\\\\x\\\\*"]
    assert _obs(r, "process.pid")[0].values == ["4"]
    assert _obs(r, "process.args")[0].values == ["-c.*"]
    assert _obs(r, "dll.Ext.device.product_id")[0].values == ["Virtual DVD-ROM", "Virtual Disk"]


def test_values_inside_string_literals_are_not_terms():
    r = extract_elastic_fields(
        'process where process.command_line : "*process.name : x*" and process.name == "a.exe"',
        language="eql",
    )
    assert [o.field for o in r.observables] == ["process.command_line", "process.name"]
    assert "x" not in r.fields_used


def test_exe_basenames_keep_dots_and_wildcard_stems():
    assert _extract_exe_names(["\\\\Syncro.Installer.exe", "C:\\\\a\\\\Microsoft.Workflow.Compiler.exe", "PAExec-*.exe"]) == [
        "syncro.installer.exe", "microsoft.workflow.compiler.exe", "paexec-*.exe",
    ]
    assert _extract_exe_names(["*\\\\cmd.exe"]) == ["cmd.exe"]


def test_kql_negated_values_stay_off_surfaces():
    r = extract_elastic_fields('process.name : "a.exe" and not process.name : "b.exe"', language="kuery")
    assert r.process_names == ["a.exe"]
