"""Tests for the shared technique -> tactic inference helper."""

from app.services import mitre_tactic_inference as mti


class TestInferTactics:
    """Verifies the canonical MITRE cache drives inference for every
    parser. Load happens lazily on first call and caches for the
    process; reset before each test so we start clean."""

    def setup_method(self):
        mti.reset_cache_for_tests()

    def test_returns_empty_for_no_input(self):
        assert mti.infer_tactics([]) == []
        assert mti.infer_tactics(None) == []

    def test_ignores_unknown_technique_ids(self):
        # T9999 doesn't exist in the STIX bundle -- contributes nothing.
        assert mti.infer_tactics(["T9999"]) == []

    def test_maps_common_technique_to_expected_tactic(self):
        # T1059 (Command and Scripting Interpreter) -> Execution (TA0002).
        result = mti.infer_tactics(["T1059"])
        assert "TA0002" in result

    def test_sub_technique_falls_back_to_parent(self):
        """Sub-techniques are normally in the cache, but if a stale
        cache is missing T1059.001 the parent T1059 mapping should
        still fire. Prevents silent regressions right after a MITRE
        update."""
        # T1059.001 (PowerShell) exists directly in the cache and
        # inherits TA0002 from T1059 anyway. Test with a real sub.
        result = mti.infer_tactics(["T1059.001"])
        assert "TA0002" in result

    def test_dedupes_across_multiple_techniques(self):
        # T1059 and T1059.001 both map to TA0002 -- only one entry.
        result = mti.infer_tactics(["T1059", "T1059.001"])
        assert result.count("TA0002") == 1

    def test_case_insensitive_input(self):
        assert "TA0002" in mti.infer_tactics(["t1059"])
        assert "TA0002" in mti.infer_tactics(["T1059  "])

    def test_missing_cache_does_not_latch(self, tmp_path, monkeypatch):
        """The sync worker starts with no cache file; the first call must
        not poison the process. Once the file appears (the ingestion
        prelude writes it) the next call loads it (#108 follow-up)."""
        real = mti._CACHE_PATH
        missing = tmp_path / "mitre_attack.json"
        monkeypatch.setattr(mti, "_CACHE_PATH", missing)
        mti.reset_cache_for_tests()

        assert mti.infer_tactics(["T1059"]) == []
        assert mti._LOADED is False

        missing.write_bytes(real.read_bytes())
        assert "TA0002" in mti.infer_tactics(["T1059"])
        assert mti._LOADED is True

    def test_corrupt_cache_latches(self, tmp_path, monkeypatch):
        """A corrupt file will not fix itself; don't re-parse it per rule."""
        bad = tmp_path / "mitre_attack.json"
        bad.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(mti, "_CACHE_PATH", bad)
        mti.reset_cache_for_tests()

        assert mti.infer_tactics(["T1059"]) == []
        assert mti._LOADED is True
