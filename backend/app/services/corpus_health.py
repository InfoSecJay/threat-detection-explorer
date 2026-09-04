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
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.services.corpus_cache import corpus_cache
from app.utils.datetime_utils import utcnow

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

_PLACEHOLDERS = frozenset({
    "unknown", "unlikely", "none", "n/a", "na", "-", "tbd", "unkown", "not known", "likely",
})


def _is_placeholder_only(values) -> bool:
    if not isinstance(values, list) or not values:
        return False
    return all(str(v).strip().lower().rstrip(".") in _PLACEHOLDERS for v in values)


def classify(mitre_techniques, references, false_positives, description) -> set[str]:
    """Which health flags one rule trips."""
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
    """{source: {"_total": n, <field>: n, ...}} from the live corpus."""
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
    for source, c in sorted(counts.items(), key=lambda kv: -kv[1]["_total"]):
        total = c["_total"]
        per = {f: c.get(f, 0) for f in fields}
        for f in fields:
            totals[f] += per[f]
        sources.append({
            "source": source,
            "total_rules": total,
            "fields": per,
            "pct": {f: _pct(per[f], total) for f in fields},
        })

    return {
        "generated_at": utcnow().isoformat(),
        "corpus": {"rules": rules, "updated_at": updated_at},
        "fields": fields,
        "field_meta": {f: {"label": label, "definition": definition} for f, (label, definition) in HEALTH_FIELDS.items()},
        "total_rules": rules,
        "totals": totals,
        "totals_pct": {f: _pct(totals[f], rules) for f in fields},
        "sources": sources,
    }


def to_csv(report: dict) -> str:
    """One row per source plus a TOTAL row; counts then percentages."""
    fields = report["fields"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source", "total_rules", *fields, *[f"{f}_pct" for f in fields]])
    for s in report["sources"]:
        w.writerow([s["source"], s["total_rules"], *[s["fields"][f] for f in fields], *[s["pct"][f] for f in fields]])
    w.writerow(["TOTAL", report["total_rules"], *[report["totals"][f] for f in fields], *[report["totals_pct"][f] for f in fields]])
    w.writerow([])
    w.writerow(["corpus_updated_at", report["corpus"]["updated_at"]])
    w.writerow(["generated_at", report["generated_at"]])
    w.writerow(["source_url", "https://detectionexplorer.io/methodology/corpus-health"])
    return buf.getvalue()
