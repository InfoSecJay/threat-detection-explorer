#!/usr/bin/env python
"""Extraction audit — measure how well the field extractor pulls
observables out of ingested rules.

Sibling to `audit_normalization.py` (which measures taxonomy classification
quality) and `audit_coverage.py` (which verifies pipeline ingest fidelity).
This one is the baseline instrument for the extracted-observables redesign
(issue #6): before we rebuild any per-source extractor, we need concrete
numbers on where extraction is failing today.

For each source, per-rule metrics computed:

  - **Coverage**: fraction of rules with ANY extracted_* field populated.
  - **Per-field population rate** for each of the 9 array-valued
    `extracted_*` fields.
  - **Query complexity distribution** (simple / moderate / complex /
    unknown) — high `unknown` rates signal the complexity heuristic
    isn't firing.
  - **Observables count distribution** — median + p95 of
    `len(extracted_observables)` per rule.
  - **Suspect-value heuristic**: how many values in the extracted
    surfaces look like extraction noise rather than real observables
    (e.g. reserved keywords, obvious junk). See `is_suspect_value()`.
  - **Field-name reasonableness**: how many `fields_used` values look
    like real dotted field paths vs raw strings.

Anomaly thresholds (heuristic):

  - `coverage < 50%` for sources that SHOULD have extraction — gap.
  - Any source with a documented "no extractor yet" flag stays silent
    (see `EXTRACTOR_STATUS`).
  - `query_complexity == "unknown"` > 20% — complexity heuristic broken.
  - `suspect_value_rate > 5%` — extractor emitting noise.

Exits 0 always — this is a report. Run any time, JSON output available
for piping.

Usage:
    python scripts/audit_extraction.py
    python scripts/audit_extraction.py --source sublime
    python scripts/audit_extraction.py --json
    python scripts/audit_extraction.py --api http://localhost:8000/api
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional


PROD_API = "https://threat-detection-explorer-production.up.railway.app/api"
PAGE_SIZE = 200
TOP_N = 10

# The nine array-valued `extracted_*` fields on DetectionListItem.
# Order matters for the per-field table rendering.
EXTRACTED_ARRAY_FIELDS = (
    "extracted_fields_used",
    "extracted_event_ids",
    "extracted_process_names",
    "extracted_file_paths",
    "extracted_registry_keys",
    "extracted_network_indicators",
    "extracted_source_tables",
    "extracted_api_actions",
    "extracted_target_resources",
)

# Extraction-status flags per source. `have_extractor` sources are
# expected to populate observables; the anomaly threshold applies.
# `no_extractor` sources are known gaps (audit-only baseline for
# future work); their low coverage doesn't fire an anomaly.
EXTRACTOR_STATUS: dict[str, str] = {
    "sigma":               "have_extractor",
    "elastic":             "have_extractor",
    "elastic_hunting":     "have_extractor",
    "elastic_protections": "have_extractor",
    "splunk":              "have_extractor",
    "sublime":             "have_extractor",
    "lolrmm":              "have_extractor",
    "sentinel":            "have_extractor",
    # These three currently skip extraction entirely — a known gap
    # tracked in issue #6. The audit reports their coverage as
    # baseline data but does NOT flag it as an anomaly.
    "google_secops":       "no_extractor",
    "okta":                "no_extractor",
    "auth0":               "no_extractor",
}

SOURCES = list(EXTRACTOR_STATUS.keys())

# Values that look like extraction bugs. Not exhaustive — this is a
# tripwire, not a validator. When a suspect value shows up in an
# `extracted_*` field it means the parser regex matched something it
# shouldn't have.
_SUSPECT_VALUE_PATTERNS = [
    # Keywords that are clearly not observables (extractor confused
    # a language keyword for a value).
    re.compile(r"^(AND|OR|NOT|WHERE|FROM|BY|STATS|KEEP|DROP|EVAL|LIMIT|SORT)$", re.IGNORECASE),
    # Empty-looking strings — should never survive the extractor
    re.compile(r"^\s*$"),
    # Common Lucene / regex meta with no actual value
    re.compile(r"^[\*\.\-_]+$"),
]

# fields_used entries should look like dotted field paths. This is
# permissive — segments can be `@timestamp`, `field-name` etc.
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_@][\w\-.@]*$")


# ── Data shapes ────────────────────────────────────────────────────


@dataclass
class SourceAudit:
    source: str
    extractor_status: str
    rule_count: int = 0

    # Coverage
    any_extraction: int = 0    # >=1 extracted_* field non-empty
    no_extraction: int = 0     # every extracted_* field empty

    # Per-field population count (how many rules have this field non-empty)
    field_population: dict[str, int] = field(default_factory=dict)

    # extracted_observables count distribution
    observables_counts: list[int] = field(default_factory=list)

    # Query complexity
    complexity_dist: Counter = field(default_factory=Counter)

    # Suspect values
    suspect_values_total: int = 0
    suspect_values_sample: list[tuple[str, str, str]] = field(default_factory=list)  # (field, value, rule_id)

    # Unreasonable field names
    unreasonable_fields_total: int = 0
    unreasonable_fields_sample: list[tuple[str, str]] = field(default_factory=list)

    anomalies: list[str] = field(default_factory=list)


# ── Helpers ────────────────────────────────────────────────────────


def pct(num: int, denom: int) -> float:
    return (100.0 * num / denom) if denom else 0.0


def fetch_page(api_base: str, source: str, offset: int) -> dict:
    q = urllib.parse.urlencode({"sources": source, "limit": PAGE_SIZE, "offset": offset})
    url = f"{api_base}/detections?{q}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read())


def fetch_all_rules(api_base: str, source: str) -> Iterable[dict]:
    offset = 0
    while True:
        page = fetch_page(api_base, source, offset)
        items = page.get("items") or []
        for item in items:
            yield item
        total = page.get("total") or 0
        offset += len(items)
        if not items or offset >= total:
            return


def is_suspect_value(value: str) -> bool:
    """True if the value looks like extractor noise."""
    if not isinstance(value, str):
        return True
    return any(p.match(value) for p in _SUSPECT_VALUE_PATTERNS)


def is_reasonable_field_name(name: str) -> bool:
    return isinstance(name, str) and bool(_FIELD_NAME_RE.match(name))


# ── Audit per source ───────────────────────────────────────────────


def audit_source(api_base: str, source: str) -> SourceAudit:
    audit = SourceAudit(
        source=source,
        extractor_status=EXTRACTOR_STATUS.get(source, "unknown"),
    )
    for f in EXTRACTED_ARRAY_FIELDS:
        audit.field_population[f] = 0

    for rule in fetch_all_rules(api_base, source):
        audit.rule_count += 1
        rule_id = str(rule.get("id") or "?")[:12]

        any_populated = False
        for f in EXTRACTED_ARRAY_FIELDS:
            vals = rule.get(f) or []
            if vals:
                audit.field_population[f] += 1
                any_populated = True
                # Suspect-value scan
                for v in vals:
                    if is_suspect_value(v):
                        audit.suspect_values_total += 1
                        if len(audit.suspect_values_sample) < 10:
                            audit.suspect_values_sample.append(
                                (f, str(v)[:60], rule_id)
                            )
                # fields_used gets an extra reasonable-name check
                if f == "extracted_fields_used":
                    for v in vals:
                        if not is_reasonable_field_name(v):
                            audit.unreasonable_fields_total += 1
                            if len(audit.unreasonable_fields_sample) < 10:
                                audit.unreasonable_fields_sample.append(
                                    (str(v)[:60], rule_id)
                                )

        audit.any_extraction += int(any_populated)
        audit.no_extraction += int(not any_populated)

        obs = rule.get("extracted_observables") or []
        audit.observables_counts.append(len(obs))
        audit.complexity_dist[rule.get("query_complexity") or "unknown"] += 1

    # ── Anomaly heuristics ─────────────────────────────────────────
    if audit.rule_count and audit.extractor_status == "have_extractor":
        coverage_pct = pct(audit.any_extraction, audit.rule_count)
        if coverage_pct < 50:
            audit.anomalies.append(
                f"extraction coverage {coverage_pct:.1f}% "
                f"({audit.any_extraction}/{audit.rule_count}) — extractor coverage gap"
            )

        unk_complexity_pct = pct(
            audit.complexity_dist.get("unknown", 0), audit.rule_count
        )
        if unk_complexity_pct > 20:
            audit.anomalies.append(
                f"query_complexity == 'unknown' for {unk_complexity_pct:.1f}% "
                f"({audit.complexity_dist.get('unknown', 0)}/{audit.rule_count}) "
                "— complexity heuristic not firing"
            )

        # Suspect values are counted per-value, not per-rule; expressed
        # as ratio to total extracted values across all fields (rough).
        total_extracted_values = sum(audit.field_population.values())
        if total_extracted_values:
            susp_pct = pct(audit.suspect_values_total, total_extracted_values)
            if susp_pct > 5:
                audit.anomalies.append(
                    f"suspect values in {susp_pct:.1f}% of extracted output "
                    f"({audit.suspect_values_total}/{total_extracted_values}) "
                    "— extractor emitting noise"
                )

        if audit.unreasonable_fields_total > 0:
            audit.anomalies.append(
                f"{audit.unreasonable_fields_total} `extracted_fields_used` "
                "entries don't look like real field names — extractor emitting "
                "raw strings or keywords"
            )

    return audit


# ── Rendering ──────────────────────────────────────────────────────


def _percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    k = int(len(ordered) * p)
    return ordered[min(k, len(ordered) - 1)]


def render_text(audit: SourceAudit) -> str:
    out: list[str] = [
        f"=== {audit.source} ({audit.extractor_status}) ===",
        f"  rules: {audit.rule_count}",
    ]
    if not audit.rule_count:
        out.append("  (no rules)")
        return "\n".join(out)

    def rate(num: int, label: str) -> str:
        return f"{num:>5} ({pct(num, audit.rule_count):>5.1f}%) {label}"

    out.append(f"  {rate(audit.any_extraction, 'rules WITH extracted observables')}")
    out.append(f"  {rate(audit.no_extraction, 'rules WITHOUT any extracted observables')}")

    out.append("  per-field population:")
    for f in EXTRACTED_ARRAY_FIELDS:
        n = audit.field_population.get(f, 0)
        out.append(f"    {n:>5} ({pct(n, audit.rule_count):>5.1f}%) {f}")

    if audit.observables_counts:
        median_ = int(statistics.median(audit.observables_counts))
        p95 = _percentile(audit.observables_counts, 0.95)
        max_ = max(audit.observables_counts)
        out.append(
            f"  observables per rule: median={median_} p95={p95} max={max_}"
        )

    out.append("  query_complexity:")
    for level, n in audit.complexity_dist.most_common():
        out.append(f"    {n:>5} ({pct(n, audit.rule_count):>5.1f}%) {level}")

    if audit.suspect_values_total:
        out.append(f"  suspect values: {audit.suspect_values_total}")
        for f, v, rid in audit.suspect_values_sample:
            out.append(f"    {f}: {v!r}  (rule {rid})")

    if audit.unreasonable_fields_total:
        out.append(f"  unreasonable field-name entries: {audit.unreasonable_fields_total}")
        for v, rid in audit.unreasonable_fields_sample:
            out.append(f"    {v!r}  (rule {rid})")

    if audit.anomalies:
        out.append("  ANOMALIES:")
        for a in audit.anomalies:
            out.append(f"    - {a}")
    return "\n".join(out)


def render_summary(audits: list[SourceAudit]) -> str:
    lines = ["=" * 60, "SUMMARY (ranked by extraction gap)"]

    def gap_score(a: SourceAudit) -> float:
        # Higher gap for lower coverage on sources that SHOULD have
        # extraction; no-extractor sources sink to the bottom.
        if a.extractor_status != "have_extractor":
            return -1.0
        return -pct(a.any_extraction, a.rule_count)  # negate for asc sort

    ranked = sorted(audits, key=gap_score)
    for a in ranked:
        cov = pct(a.any_extraction, a.rule_count)
        status = a.extractor_status
        marker = "clean" if not a.anomalies else f"{len(a.anomalies)} anomalies"
        lines.append(
            f"  {a.source:22s} rules={a.rule_count:>5} "
            f"coverage={cov:>5.1f}%  status={status:<14} [{marker}]"
        )
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(
        description="Extraction audit for the Detection Explorer catalog. "
        "Baseline instrument for the extracted-observables redesign (issue #6)."
    )
    p.add_argument("--source", help="Run only for one source by name.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--api", default=PROD_API, help=f"API base (default: {PROD_API}).")
    args = p.parse_args()

    sources = SOURCES
    if args.source:
        if args.source not in SOURCES:
            sys.stderr.write(
                f"unknown source: {args.source}. Known: {', '.join(SOURCES)}\n"
            )
            return 2
        sources = [args.source]

    audits: list[SourceAudit] = []
    for src in sources:
        sys.stderr.write(f"-- {src}: paginating /api/detections...\n")
        try:
            audit = audit_source(args.api, src)
        except urllib.error.URLError as e:
            sys.stderr.write(f"   ERROR fetching {src}: {e}\n")
            continue
        audits.append(audit)
        if not args.json:
            sys.stdout.write(render_text(audit) + "\n\n")

    if args.json:
        # Counters aren't JSON-serializable directly.
        def _serialize(a: SourceAudit) -> dict:
            d = asdict(a)
            d["complexity_dist"] = dict(a.complexity_dist)
            return d
        sys.stdout.write(json.dumps([_serialize(a) for a in audits], indent=2) + "\n")
    else:
        sys.stdout.write(render_summary(audits) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
