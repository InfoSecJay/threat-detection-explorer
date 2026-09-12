"""What counts as technique COVERAGE (DX-05 / #147), and for whom (#143).

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

``CoverageScope`` (#143 / DX-01) narrows the same question to one
reader's stack: score coverage against only the repos they run
(``?sources=sigma,elastic``), and optionally bring the excluded
modalities back in (``?coverage=all``) for anyone who wants the old
any-tag count. Deprecated rules stay out under every scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.models.detection import Detection
from app.services.repository_sync import ALL_REPOSITORY_NAMES
from app.services.taxonomy.canonical import COVERAGE_EXCLUDED_MODALITIES


@dataclass(frozen=True)
class CoverageScope:
    """Which rules count as coverage for one request.

    ``sources``: the repos to score against; None means every tracked
    source. ``include_excluded``: count the hunting / building-block /
    passthrough / indicator rules too (the pre-#147 behaviour).
    """

    sources: Optional[frozenset[str]] = None
    include_excluded: bool = False

    @property
    def is_default(self) -> bool:
        return self.sources is None and not self.include_excluded

    def key(self) -> tuple:
        """Hashable cache key (frozensets are hashable, but a sorted
        tuple reads better in a debug dump)."""
        return (tuple(sorted(self.sources)) if self.sources is not None else None, self.include_excluded)

    def describe(self) -> dict:
        """What the API echoes back so the UI can label the numbers."""
        return {
            "sources": sorted(self.sources) if self.sources is not None else None,
            "coverage": "all" if self.include_excluded else "strict",
        }

    def allows_source(self, source: str) -> bool:
        return self.sources is None or source in self.sources


DEFAULT_SCOPE = CoverageScope()


def parse_scope(sources: Optional[str], coverage: Optional[str]) -> CoverageScope:
    """Build a scope from the ``sources=`` (comma-separated) and
    ``coverage=`` (strict | all) query params. Raises ValueError with a
    message fit for a 400 on an unknown source or coverage value; an
    empty ``sources`` means "every source", not "no source"."""
    names: Optional[frozenset[str]] = None
    if sources is not None:
        wanted = {s.strip() for s in sources.split(",") if s.strip()}
        unknown = sorted(wanted - set(ALL_REPOSITORY_NAMES))
        if unknown:
            raise ValueError(
                f"Unknown source(s): {', '.join(unknown)}. Expected any of {', '.join(ALL_REPOSITORY_NAMES)}."
            )
        if wanted and wanted != set(ALL_REPOSITORY_NAMES):
            names = frozenset(wanted)
    mode = (coverage or "strict").lower()
    if mode not in ("strict", "all"):
        raise ValueError(f"Unknown coverage value: {coverage!r}. Expected 'strict' or 'all'.")
    return CoverageScope(sources=names, include_excluded=(mode == "all"))


def coverage_conditions(scope: Optional[CoverageScope] = None) -> list:
    """SQLAlchemy conditions that keep only rules which count as coverage
    under ``scope`` (the default scope when omitted)."""
    scope = scope or DEFAULT_SCOPE
    conds = [Detection.status != "deprecated"]
    if not scope.include_excluded:
        conds.append(Detection.rule_modality.notin_(sorted(COVERAGE_EXCLUDED_MODALITIES)))
    if scope.sources is not None:
        conds.append(Detection.source.in_(sorted(scope.sources)))
    return conds


def counts_as_coverage(status: str | None, rule_modality: str | None) -> bool:
    """Python-side twin of the default ``coverage_conditions()`` for scans
    that need the excluded rows for something else (the actor bundle
    still indexes a passthrough rule named after an actor as a Named
    rule). Source scoping is applied by the caller."""
    if status == "deprecated":
        return False
    return (rule_modality or "rule") not in COVERAGE_EXCLUDED_MODALITIES
