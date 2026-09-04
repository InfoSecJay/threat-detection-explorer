"""Corpus-health report (#124 / teardown F2).

The numbers nobody else publishes: across the whole corpus, how many
rules ship with no ATT&CK mapping, no references, no false-positive
notes (or only a placeholder such as "Unknown"), and no description --
per source and in total. Computed live from the same rows the catalog
serves, cached per corpus fingerprint, so the report is exactly as
current as the site. The CSV is the same table for people who want to
cite the data rather than the page.

Definitions are deliberately literal so they can be checked against the
rule page of any listed rule:

- no ATT&CK mapping: ``mitre_techniques`` is empty (declared or derived)
- no references: ``references`` is empty
- no FP notes: ``false_positives`` is empty
- placeholder FP notes: ``false_positives`` is non-empty but every entry
  is a stock word (unknown, unlikely, none, n/a ...) -- a field filled to
  pass a linter, not to help an analyst
- no description: ``description`` is null or whitespace

Honesty rule: a format that has no field for something cannot be blamed
for leaving it empty. Sentinel analytic templates and Elastic
Protections TOML carry no references field; Sublime, Sentinel, Elastic
Protections, Google SecOps and Elastic hunting queries carry no
false-positives field. Those cells are reported as not applicable, and
every headline percentage is computed twice: literally over all rules,
and over the rules whose format can express the field ("applicable
basis"), which is the number to quote. The capability map is the same
one the metadata completeness score uses (quality_score.INAPPLICABLE).
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.services.quality_score import INAPPLICABLE
from app.utils.datetime_utils import utcnow

try:  # the score's boilerplate list is the same "stock word" notion
    from app.services.quality_score import _BOILERPLATE_FPS as _SCORE_BOILERPLATE
except ImportError:  # pragma: no cover - defensive
    _SCORE_BOILERPLATE = frozenset()

# field -> (label, one-line definition shown next to the number)
HEALTH_FIELDS: dict[str, tuple[str, str]] = {
    "no_attack": (
        "No ATT&CK mapping",
        "mitre_techniques is empty: the rule declares no technique and none could be derived from its tags or metadata.",
    ),
    "no_references": (
        "No references",
        "references is empty: no research, advisory, or write-up is cited for why the logic exists.",
    ),
    "no_false_positives": (
        "No false-positive notes",
        "false_positives is empty: the author documented no benign scenario an analyst should expect.",
    ),
    "placeholder_false_positives": (
        "Placeholder FP notes only",
        "false_positives is non-empty but every entry is a stock word (unknown, unlikely, none, n/a): filled in, not thought through.",
    ),
    "no_description": (
        "No description",
        "description is empty: nothing beyond the title explains what the rule looks for.",
    ),
}

# Which quality-score capability each health field depends on. Fields
# absent here (ATT&CK, description) apply to every format: every source
# either declares techniques or has them derived, and every rule format
# has a description slot.
_FIELD_CAPABILITY: dict[str, str] = {
    "no_references": "references",
    "no_false_positives": "false_positives",
    "placeholder_false_positives": "false_positives",
}

_PLACEHOLDERS = frozenset({
    "unknown", "unlikely", "none", "n/a", "na", "-", "tbd", "unkown", "not known", "likely",
}) | frozenset(str(x).strip().lower() for x in _SCORE_BOILERPLATE)


def not_applicable_for(source: str) -> list[str]:
    """Health fields a source's format cannot express (in HEALTH_FIELDS order)."""
    caps = INAPPLICABLE.get(source, frozenset())
    return [f for f in HEALTH_FIELDS if _FIELD_CAPABILITY.get(f) in caps]


def _is_placeholder_only(values) -> bool:
    if not isinstance(values, list) or not values:
        return False
    return all(str(v).strip().lower().rstrip(".") in _PLACEHOLDERS for v in values)


def classify(mitre_techniques, references, false_positives, description) -> set[str]:
    """Which health flags one rule trips (format capability not considered)."""
    flags: set[str] = set()
    if not mitre_techniques:
        flags.add("no_attack")
    if not references:
        flags.add("no_references")
    if not false_positives:
        flags.add("no_false_positives")
    elif _is_placeholder_only(false_positives):
        flags.add("placeholder_false_positives")
    if not (description or "").strip():
        flags.add("no_description")
    return flags


async def current_counts(db: AsyncSession) -> dict[str, dict[str, int]]:
    """{source: {"_total": n, <field>: n, ...}} from the live corpus, literal."""
    rows = (
        await db.execute(
            select(
                Detection.source,
                Detection.mitre_techniques,
                Detection.references,
                Detection.false_positives,
                Detection.description,
            )
        )
    ).all()
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for source, mt, refs, fps, desc in rows:
        out[source]["_total"] += 1
        for flag in classify(mt, refs, fps, desc):
            out[source][flag] += 1
    return {s: dict(v) for s, v in out.items()}


def _pct(n: int, of: int) -> float:
    return round(100.0 * n / of, 1) if of else 0.0


async def build_report(db: AsyncSession) -> dict:
    counts = await current_counts(db)
    fields = list(HEALTH_FIELDS)
    rules, updated_at = await corpus_cache.fingerprint(db)

    sources = []
    totals: dict[str, int] = {f: 0 for f in fields}
    applicable_count: dict[str, int] = {f: 0 for f in fields}
    applicable_of: dict[str, int] = {f: 0 for f in fields}
    for source, c in sorted(counts.items(), key=lambda kv: -kv[1]["_total"]):
        total = c["_total"]
        na = not_applicable_for(source)
        per = {f: c.get(f, 0) for f in fields}
        for f in fields:
            totals[f] += per[f]
            if f not in na:
                applicable_count[f] += per[f]
                applicable_of[f] += total
        sources.append({
            "source": source,
            "total_rules": total,
            "not_applicable": na,
            "fields": {f: (0 if f in na else per[f]) for f in fields},
            "pct": {f: (None if f in na else _pct(per[f], total)) for f in fields},
        })

    return {
        "generated_at": utcnow().isoformat(),
        "corpus": {"rules": rules, "updated_at": updated_at},
        "fields": fields,
        "field_meta": {f: {"label": label, "definition": definition} for f, (label, definition) in HEALTH_FIELDS.items()},
        "total_rules": rules,
        # Literal: every rule counted, whether or not its format has the field.
        "totals": totals,
        "totals_pct": {f: _pct(totals[f], rules) for f in fields},
        # Applicable basis: only rules whose format can express the field. Quote these.
        "applicable": {
            f: {"count": applicable_count[f], "of": applicable_of[f], "pct": _pct(applicable_count[f], applicable_of[f])}
            for f in fields
        },
        "sources": sources,
    }


def to_csv(report: dict) -> str:
    """One row per source, then TOTAL (literal) and APPLICABLE rows."""
    fields = report["fields"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source", "total_rules", *fields, *[f"{f}_pct" for f in fields], "not_applicable"])
    for s in report["sources"]:
        w.writerow([
            s["source"], s["total_rules"],
            *["n/a" if f in s["not_applicable"] else s["fields"][f] for f in fields],
            *["n/a" if f in s["not_applicable"] else s["pct"][f] for f in fields],
            ";".join(s["not_applicable"]),
        ])
    w.writerow(["TOTAL", report["total_rules"], *[report["totals"][f] for f in fields], *[report["totals_pct"][f] for f in fields], ""])
    a = report["applicable"]
    w.writerow(["APPLICABLE_RULES", "", *[a[f]["of"] for f in fields], *["" for _ in fields], "rules whose format can express the field"])
    w.writerow(["APPLICABLE", "", *[a[f]["count"] for f in fields], *[a[f]["pct"] for f in fields], "quote these percentages"])
    w.writerow([])
    w.writerow(["corpus_updated_at", report["corpus"]["updated_at"]])
    w.writerow(["generated_at", report["generated_at"]])
    w.writerow(["source_url", "https://detectionexplorer.io/methodology/corpus-health"])
    return buf.getvalue()
