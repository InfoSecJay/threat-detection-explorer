"""Observables v2: the typed observables reach the export."""

from app.api.routes.export import _observables_cell


def test_observables_cell_flattens_typed_rows():
    cell = _observables_cell([
        {"field": "Image", "values": ["powershell.exe", "pwsh.exe"],
         "type": "process", "subtype": "process_name", "negated": False},
        {"field": "DestinationPort", "values": ["443"],
         "type": "network", "subtype": "port", "negated": True},
    ])
    assert cell == (
        "process/process_name Image=powershell.exe|pwsh.exe; "
        "NOT network/port DestinationPort=443"
    )


def test_observables_cell_tolerates_junk():
    assert _observables_cell(None) == ""
    assert _observables_cell([]) == ""
    assert _observables_cell(["not-a-dict", {"field": "x", "values": None, "type": "t", "subtype": "s"}]) == "t/s x="
