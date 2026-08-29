"""Per-vendor normalizer tests for SigmaNormalizer.

Each per-vendor test file follows the same shape:

  1. Build a representative ParsedRule using a small ``_parsed()``
     helper. Defaults satisfy every required field; tests override
     only the bits they care about.
  2. Invoke ``normalizer.normalize(parsed)``.
  3. Assert on the resulting NormalizedDetection — focused on what's
     distinctive about THIS vendor: the canonical-taxonomy resolution,
     extracted observables, status/severity normalization, and any
     vendor-specific quirks (Sigma `level` → severity mapping, the
     dot-separated tag format for MITRE etc.).

These tests are the safety net that lets us refactor parsers and
normalizers without breaking the pipeline silently.
"""

from __future__ import annotations

import pytest

from app.normalizers.sigma import SigmaNormalizer
from app.parsers.base import ParsedRule


def _parsed(**overrides) -> ParsedRule:
    """Build a Sigma-shaped ParsedRule with sensible defaults."""
    defaults = dict(
        source="sigma",
        file_path="rules/windows/process_creation/proc_creation_susp_powershell.yml",
        raw_content="placeholder yaml",
        title="Suspicious PowerShell Encoded Command",
        detection_logic_raw={
            "selection": {
                "EventID": 4688,
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": ["-enc", "-EncodedCommand"],
            },
            "condition": "selection",
        },
        description="Detects encoded PowerShell command line",
        author="Detection Engineer",
        status="stable",
        severity="high",
        log_source={"product": "windows", "category": "process_creation"},
        tags=["attack.execution", "attack.defense_evasion"],
        mitre_attack={
            "tactics": ["TA0002"],
            "techniques": ["T1059.001"],
        },
        false_positives=["Legitimate admin scripts"],
        extra={
            "id": "fc99a948-6e26-4339-9d3d-c9450f60af26",
            "references": ["https://example.com/threat-intel"],
            "date": "2023/01/01",
            "modified": "2024/05/15",
        },
    )
    defaults.update(overrides)
    return ParsedRule(**defaults)


@pytest.fixture
def normalizer():
    """A SigmaNormalizer without a repo_path (no git fallback needed)."""
    return SigmaNormalizer("https://github.com/SigmaHQ/sigma")


# ── Identity / metadata pass-through ──────────────────────────────────


def test_normalize_preserves_metadata(normalizer):
    parsed = _parsed()
    n = normalizer.normalize(parsed)

    assert n.source == "sigma"
    assert n.title == "Suspicious PowerShell Encoded Command"
    assert n.description == "Detects encoded PowerShell command line"
    assert n.author == "Detection Engineer"
    assert n.rule_id == "fc99a948-6e26-4339-9d3d-c9450f60af26"
    assert n.references == ["https://example.com/threat-intel"]
    assert n.language == "sigma"


def test_normalize_generates_deterministic_id(normalizer):
    """Same source + file_path → same id (drives the upsert key)."""
    n1 = normalizer.normalize(_parsed())
    n2 = normalizer.normalize(_parsed())
    assert n1.id == n2.id


def test_normalize_generates_distinct_ids_per_file(normalizer):
    n1 = normalizer.normalize(_parsed(file_path="rules/windows/a.yml"))
    n2 = normalizer.normalize(_parsed(file_path="rules/windows/b.yml"))
    assert n1.id != n2.id


# ── Status + severity ────────────────────────────────────────────────


def test_normalize_status_stable(normalizer):
    assert normalizer.normalize(_parsed(status="stable")).status == "stable"


def test_normalize_status_test_is_preserved(normalizer):
    # Sigma vocabulary 1:1 (issue #26): `test` is its own maturity level,
    # no longer flattened into `experimental`.
    assert normalizer.normalize(_parsed(status="test")).status == "test"
    assert normalizer.normalize(_parsed(status="unsupported")).status == "unsupported"


def test_normalize_status_deprecated(normalizer):
    assert normalizer.normalize(_parsed(status="deprecated")).status == "deprecated"


def test_normalize_severity_critical(normalizer):
    assert normalizer.normalize(_parsed(severity="critical")).severity == "critical"


def test_normalize_severity_unknown_falls_through(normalizer):
    assert normalizer.normalize(_parsed(severity="bogus")).severity == "unknown"


# ── MITRE pass-through ───────────────────────────────────────────────


def test_normalize_passes_mitre_through(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.mitre_tactics == ["TA0002"]
    assert n.mitre_techniques == ["T1059.001"]


def test_normalize_handles_missing_mitre(normalizer):
    n = normalizer.normalize(_parsed(mitre_attack={}))
    assert n.mitre_tactics == []
    assert n.mitre_techniques == []


# ── Canonical taxonomy resolution ────────────────────────────────────


def test_normalize_resolves_canonical_taxonomy_for_windows_process(normalizer):
    """A windows/process_creation Sigma rule should resolve to canonical
    `windows` platform + `process` event_type. The taxonomy resolver
    is the single most important per-vendor behavior — this test pins
    it."""
    n = normalizer.normalize(_parsed())
    assert "windows" in n.platforms
    assert "process_creation" in n.event_types
    assert n.taxonomy_matched is True
    assert n.taxonomy_fingerprint, "fingerprint should be populated"


def test_normalize_unmapped_logsource_falls_through_to_unknown(normalizer):
    """A logsource the resolver doesn't recognise must still produce
    valid canonical lists (always at least `["unknown"]`) and signal
    `taxonomy_matched=False` for the drift report."""
    n = normalizer.normalize(
        _parsed(log_source={"product": "totally_made_up_product"})
    )
    assert n.platforms == ["unknown"]
    assert n.data_sources == ["unknown"]
    assert n.event_types == ["unknown"]
    assert n.taxonomy_matched is False


# ── Extracted observables ────────────────────────────────────────────


def test_normalize_extracts_event_ids_from_detection(normalizer):
    n = normalizer.normalize(_parsed())
    assert "4688" in n.extracted_event_ids


def test_normalize_extracts_process_name_from_detection(normalizer):
    n = normalizer.normalize(_parsed())
    assert any("powershell.exe" in p.lower() for p in n.extracted_process_names)


def test_normalize_query_complexity_is_classified(normalizer):
    """Sigma extractor always sets query_complexity to one of the
    canonical values (simple/moderate/complex/unknown)."""
    n = normalizer.normalize(_parsed())
    assert n.query_complexity in {"simple", "moderate", "complex", "unknown"}


# ── Dates ─────────────────────────────────────────────────────────────


def test_normalize_uses_embedded_dates_when_present(normalizer):
    n = normalizer.normalize(_parsed())
    assert n.rule_created_date is not None
    assert n.rule_created_date.year == 2023
    assert n.rule_modified_date is not None
    assert n.rule_modified_date.year == 2024


def test_normalize_handles_missing_dates(normalizer):
    """No embedded date and no git fallback (no repo_path) → None."""
    n = normalizer.normalize(_parsed(extra={"id": "x"}))
    assert n.rule_created_date is None
    assert n.rule_modified_date is None


# ── Source rule URL ──────────────────────────────────────────────────


def test_normalize_builds_source_rule_url(normalizer):
    """The deep-link URL into the source repo should embed the file path."""
    n = normalizer.normalize(_parsed())
    assert n.source_rule_url is not None
    assert "SigmaHQ/sigma" in n.source_rule_url
    assert "proc_creation_susp_powershell.yml" in n.source_rule_url
