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
# gap -> partial -> max, on the site's palette.
LAYER_GRADIENT = ["#ff0040", "#ffaa33", "#00ffcc"]


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
        "gradient": {"colors": LAYER_GRADIENT, "minValue": 0, "maxValue": max(max_score, 1)},
        "legendItems": [
            {"color": LAYER_GRADIENT[0], "label": "0 rules - detection gap"},
            {"color": LAYER_GRADIENT[1], "label": "partial rule coverage"},
            {"color": LAYER_GRADIENT[2], "label": f"{max(max_score, 1)} rules (max observed)"},
        ],
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
