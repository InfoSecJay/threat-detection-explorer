"""What counts as technique COVERAGE (DX-05 / #147).

Three coverage scans -- the actor score bundle, the ATT&CK matrix and
the data-source heatmap -- each read every rule that carries a
technique tag. That let a hunting query nobody alerts on, a building
block that never fires alone, an alert forwarded from another product
and a hash list all count as "a rule for T1055", and those counts fed
the actor pages' coverage percentages and the Navigator export.

One set of conditions, applied at the query, so the three scans and
anything added later agree. Deprecated rules are excluded on the same
grounds the default catalog view excludes them (#109). The catalog,
facets and search are NOT scoped by this: a passthrough rule is still
a rule you can find, it just is not evidence of coverage.
"""

from __future__ import annotations

from app.models.detection import Detection
from app.services.taxonomy.canonical import COVERAGE_EXCLUDED_MODALITIES


def coverage_conditions() -> list:
    """SQLAlchemy conditions that keep only rules which count as coverage."""
    return [
        Detection.status != "deprecated",
        Detection.rule_modality.notin_(sorted(COVERAGE_EXCLUDED_MODALITIES)),
    ]


def counts_as_coverage(status: str | None, rule_modality: str | None) -> bool:
    """Python-side twin of `coverage_conditions()` for scans that need the
    excluded rows for something else (the actor bundle still indexes a
    passthrough rule named after an actor as a Named rule)."""
    if status == "deprecated":
        return False
    return (rule_modality or "rule") not in COVERAGE_EXCLUDED_MODALITIES
