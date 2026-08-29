"""Every taxonomy mapping file must reference only canonical values.

The runtime loader only WARNS on drift so a typo cannot take ingestion
down; that made `endpoint_behavior` (used by panther.yaml as an
event_type while it was only a data_source) reach production on 63
rules unnoticed (issue #42). This test is the gate the warning is not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.taxonomy._loader import _MAPPINGS_DIR, load_mapping
from app.services.taxonomy.canonical import EVENT_TYPES

MAPPING_FILES = sorted(p.stem for p in Path(_MAPPINGS_DIR).glob("*.yaml"))


def test_mapping_files_are_discovered():
    assert "sigma" in MAPPING_FILES and "panther" in MAPPING_FILES


@pytest.mark.parametrize("vendor", MAPPING_FILES)
def test_mapping_references_only_canonical_values(vendor):
    load_mapping(vendor, strict=True)


def test_strict_mode_raises_on_drift(tmp_path, monkeypatch):
    import app.services.taxonomy._loader as loader

    bad = tmp_path / "bogus.yaml"
    bad.write_text("by_key:\n  x:\n    event_types: [not_a_real_type]\n", encoding="utf-8")
    monkeypatch.setattr(loader, "_MAPPINGS_DIR", tmp_path)
    with pytest.raises(ValueError, match="not_a_real_type"):
        loader.load_mapping("bogus", strict=True)
    # Non-strict keeps the historical behaviour: warn, return the data.
    assert loader.load_mapping("bogus")["by_key"]["x"]["event_types"] == ["not_a_real_type"]


def test_endpoint_behavior_is_a_canonical_event_type():
    assert "endpoint_behavior" in EVENT_TYPES
