"""Navigator layer coloring (DX-03): a technique with real coverage must
never render in the same color band as a true zero-rule gap, no matter
how large the best-covered technique in the layer is."""

from app.services.navigator import build_layer, _bin_color


def test_bin_color_separates_partial_coverage_from_a_gap():
    assert _bin_color(0) == "#ff0040"
    assert _bin_color(1) != "#ff0040"
    assert _bin_color(55) not in ("#ff0040", "#ff6b35")
    assert _bin_color(829) == "#00ffcc"


def test_build_layer_colors_each_technique_by_its_own_bin_not_the_corpus_max():
    layer = build_layer(
        name="test",
        description="test",
        technique_scores={"T1003.002": 55, "T1566.002": 829, "T1000": 0},
        technique_comments={},
        metadata=[],
    )
    colors = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
    # 55 rules must not look like a gap just because another technique has 829.
    assert colors["T1000"] == "#ff0040"
    assert colors["T1003.002"] not in ("#ff0040", "#ff6b35")
    assert colors["T1003.002"] != colors["T1000"]
    assert len(layer["legendItems"]) == 5
