"""ATT&CK Navigator layer builder, shared by the actor endpoints and the
catalog export ("this query as a layer").

Layer format 4.5 / Navigator 5.x. Techniques with zero rules stay
enabled and scored 0 -- a gap is the point of the visualization.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from fastapi.responses import JSONResponse

from app.services.mitre import mitre_service

NAVIGATOR_VERSION = "5.1.0"
LAYER_FORMAT = "4.5"

# DX-03: a linear gradient across the whole corpus painted a technique
# with 55 rules almost the same red as a true zero-rule gap, because
# the scale ran to whatever the single best-covered technique scored
# (829, in one case). Bin instead: each technique gets an explicit
# `color` (Navigator honors a per-technique color over the gradient),
# so "some coverage" can never render in the "no coverage" band.
_SCORE_BINS: list[tuple[int, int | None, str, str]] = [
    (0, 0, "#ff0040", "0 rules - detection gap"),
    (1, 1, "#ff6b35", "1 rule"),
    (2, 5, "#ffaa33", "2-5 rules"),
    (6, 20, "#8ecc6b", "6-20 rules"),
    (21, None, "#00ffcc", "21+ rules"),
]


def _bin_color(score: int) -> str:
    for lo, hi, color, _label in _SCORE_BINS:
        if score >= lo and (hi is None or score <= hi):
            return color
    return _SCORE_BINS[-1][2]  # unreachable; last bin's hi is None


def build_layer(
    *,
    name: str,
    description: str,
    technique_scores: dict[str, int],
    technique_comments: dict[str, str],
    metadata: list[dict],
) -> dict:
    max_score = max(technique_scores.values(), default=0)
    techniques = [
        {
            "techniqueID": tid,
            "score": score,
            "color": _bin_color(score),
            "comment": technique_comments.get(tid, ""),
            "enabled": True,
            "showSubtechniques": False,
        }
        for tid, score in sorted(technique_scores.items())
    ]
    return {
        "name": name,
        "versions": {
            "attack": mitre_service.get_attack_version() or "unknown",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT,
        },
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        # Every technique above carries an explicit `color`, so this
        # gradient is only Navigator's own legend-bar decoration, not
        # what colors a cell -- kept monotonic gap -> max for that bar.
        "gradient": {
            "colors": [b[2] for b in _SCORE_BINS],
            "minValue": 0,
            "maxValue": max(max_score, 1),
        },
        "legendItems": [{"color": color, "label": label} for _lo, _hi, color, label in _SCORE_BINS],
        "metadata": metadata,
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def layer_from_rules(
    rules: Iterable[tuple[str, str, list[str] | None, str]],
    *,
    name: str,
    description: str,
    metadata: list[dict],
    max_comment_titles: int = 5,
) -> dict:
    """Layer scored by rule count per technique over `(id, title,
    mitre_techniques, source)` rows; comments list up to N rule titles
    with their source so the layer reads on its own."""
    scores: Counter[str] = Counter()
    titles: dict[str, list[str]] = defaultdict(list)
    for _rid, title, techniques, source in rules:
        for tid in techniques or []:
            if not isinstance(tid, str) or not tid:
                continue
            tid_u = tid.upper()
            scores[tid_u] += 1
            if len(titles[tid_u]) < max_comment_titles:
                titles[tid_u].append(f"[{source}] {title}")
    comments = {
        tid: "\n".join(t) + (f"\n... and {scores[tid] - len(t)} more" if scores[tid] > len(t) else "")
        for tid, t in titles.items()
    }
    return build_layer(
        name=name, description=description, technique_scores=dict(scores),
        technique_comments=comments, metadata=metadata,
    )


def layer_response(layer: dict, filename: str) -> JSONResponse:
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
