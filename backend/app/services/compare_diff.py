"""Observable-level diff of 2-6 rules (#11).

The old side-by-side compared metadata columns, which any table can
do. What the corpus can say that nothing else can is *what each rule
keys on*: the typed observables the extractors pull out of the logic.
Two rules for the same technique that test different process names,
or one that excludes exactly what the other matches, differ in ways a
metadata grid never shows.

Pure function over Detection rows so it is testable without a DB; the
route only loads the rows. Values compare case-insensitively (the
extractors keep vendor casing: `Rundll32.exe` and `rundll32.exe` are
the same observable); the first spelling seen is the one displayed.
"""

from __future__ import annotations

from typing import Callable, Optional

TYPE_ORDER: tuple[str, ...] = (
    "process", "file", "registry", "network", "dns", "email", "cloud",
    "identity", "authentication", "endpoint", "event", "other",
)

# Metadata axes the matrix also shows, one row per distinct value.
AXES: tuple[tuple[str, Callable], ...] = (
    ("mitre_techniques", lambda d: d.mitre_techniques),
    ("mitre_tactics", lambda d: d.mitre_tactics),
    ("data_sources", lambda d: d.data_sources),
    ("platforms", lambda d: d.platforms),
    ("domains", lambda d: getattr(d, "domains", None)),
    ("products", lambda d: getattr(d, "products", None)),
    ("event_types", lambda d: d.event_types),
    ("source_tables", lambda d: getattr(d, "extracted_source_tables", None)),
    ("fields", lambda d: getattr(d, "extracted_fields_used", None)),
)


def _norm(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v.lower() if v else None


def _rule_card(d) -> dict:
    obs = [o for o in (getattr(d, "extracted_observables", None) or []) if isinstance(o, dict)]
    return {
        "id": d.id,
        "title": d.title,
        "source": d.source,
        "severity": d.severity,
        "status": d.status,
        "language": d.language,
        "rule_modality": getattr(d, "rule_modality", None),
        "platforms": [v for v in (d.platforms or []) if isinstance(v, str)],
        "data_sources": [v for v in (d.data_sources or []) if isinstance(v, str)],
        "event_types": [v for v in (d.event_types or []) if isinstance(v, str)],
        "mitre_tactics": [v for v in (d.mitre_tactics or []) if isinstance(v, str)],
        "mitre_techniques": [v for v in (d.mitre_techniques or []) if isinstance(v, str)],
        "quality_score": getattr(d, "quality_score", None),
        "query_complexity": getattr(d, "query_complexity", None),
        "source_rule_url": getattr(d, "source_rule_url", None),
        "observable_count": sum(
            len([v for v in (o.get("values") or []) if _norm(v)]) for o in obs
        ),
    }


def _axis(rules: list, getter: Callable) -> list[dict]:
    seen: dict[str, dict] = {}
    for d in rules:
        for v in getter(d) or []:
            if not isinstance(v, str) or not v.strip():
                continue
            entry = seen.setdefault(v, {"value": v, "present_in": []})
            if d.id not in entry["present_in"]:
                entry["present_in"].append(d.id)
    return sorted(seen.values(), key=lambda e: (-len(e["present_in"]), e["value"]))


def compute_observable_diff(rules: list) -> dict:
    """Matrix of every observable and metadata value across `rules`.

    observables: one row per (type, subtype, value) with the rules it is
    present in, the rules where it is an exclusion (`negated_in`), and
    the source field each rule tests it on -- the field names are the
    cross-vendor Rosetta stone (`Image` / `process.name` / `NewProcessName`).
    """
    ids = [d.id for d in rules]
    n = len(ids)

    table: dict[tuple[str, str, str], dict] = {}
    for d in rules:
        for o in getattr(d, "extracted_observables", None) or []:
            if not isinstance(o, dict):
                continue
            otype = o.get("type") if o.get("type") in TYPE_ORDER else "other"
            subtype = o.get("subtype") if isinstance(o.get("subtype"), str) else ""
            field = o.get("field") if isinstance(o.get("field"), str) else ""
            negated = bool(o.get("negated"))
            for raw in o.get("values") or []:
                key_value = _norm(raw)
                if key_value is None:
                    continue
                entry = table.setdefault(
                    (otype, subtype, key_value),
                    {"type": otype, "subtype": subtype, "value": raw.strip(),
                     "present_in": [], "negated_in": [], "fields": {}},
                )
                if d.id not in entry["present_in"]:
                    entry["present_in"].append(d.id)
                if negated and d.id not in entry["negated_in"]:
                    entry["negated_in"].append(d.id)
                if field:
                    fields = entry["fields"].setdefault(d.id, [])
                    if field not in fields:
                        fields.append(field)

    observables = list(table.values())
    for e in observables:
        e["shared"] = len(e["present_in"]) == n
    observables.sort(
        key=lambda e: (TYPE_ORDER.index(e["type"]), -len(e["present_in"]), e["subtype"], e["value"].lower())
    )

    unique = {i: 0 for i in ids}
    for e in observables:
        if len(e["present_in"]) == 1:
            unique[e["present_in"][0]] += 1

    # One rule matches a value another rule excludes: the sharpest
    # difference two rules can have, worth calling out on its own.
    contradictions = []
    for e in observables:
        matched = [i for i in e["present_in"] if i not in e["negated_in"]]
        if e["negated_in"] and matched:
            contradictions.append({
                "type": e["type"], "subtype": e["subtype"], "value": e["value"],
                "matched_in": matched, "excluded_in": list(e["negated_in"]),
            })

    axes = {name: _axis(rules, getter) for name, getter in AXES}
    return {
        "rules": [_rule_card(d) for d in rules],
        "observables": observables,
        "axes": axes,
        "summary": {
            "rules": n,
            "observables": len(observables),
            "shared_by_all": sum(1 for e in observables if e["shared"]),
            "unique_by_rule": unique,
            "shared_techniques": [a["value"] for a in axes["mitre_techniques"] if len(a["present_in"]) == n],
            "contradictions": contradictions,
        },
    }
