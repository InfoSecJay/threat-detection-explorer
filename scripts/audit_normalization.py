#!/usr/bin/env python
"""Normalization audit -- measure how well the rules we ingested are
classified.

Phase 1 (`audit_coverage.py`) verifies the pipeline ingests every rule
upstream has. Phase 2 (this script) verifies the rules we ingest get
classified correctly. The user-spotted finding *"majority of Sentinel
rules are cross_platform"* is exactly the class of bug this surfaces
programmatically.

For each source the script fetches every rule from production via the
public API, then computes:

  - Distribution of the three canonical taxonomy fields
    (`taxonomy_platforms`, `taxonomy_data_sources`, `taxonomy_event_types`)
    with top values + count + share of the source.
  - % rules whose canonical platform / data-source / event-type is just
    `["unknown"]` (resolver fell through entirely).
  - % rules whose `taxonomy_platforms` contains `cross_platform` -- the
    coarse fallback that often hides resolver gaps.
  - % rules with any extracted observables (any `extracted_*` populated).
  - % rules with no MITRE techniques.
  - `language` distribution per source (sanity check -- Splunk should be
    100% spl, Sentinel 100% kql, etc.).
  - Legacy `platform` vs canonical `taxonomy_platforms` disagreement
    count -- when they disagree the legacy column is probably wrong
    (will be removed in Phase 3 of the taxonomy migration).

Then a set of anomaly heuristics flag issues to investigate:

  - `unknown_platform_rate > 5%`      taxonomy mapping gap
  - `cross_platform_rate > 5%`        likely an over-broad fallback
                                      (the user's specific Sentinel concern)
  - `no_extracted_observables_rate > 30%`   parser/extractor regression
  - language doesn't match the source's expected language

Exits 0 always -- this is a report. Run any time, JSON output available
for piping.

Usage:
    python scripts/audit_normalization.py
    python scripts/audit_normalization.py --source sentinel
    python scripts/audit_normalization.py --json
    python scripts/audit_normalization.py --api http://localhost:8000/api
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional


PROD_API = "https://threat-detection-explorer-production.up.railway.app/api"
PAGE_SIZE = 200  # API caps at 200 per request
TOP_N = 10        # how many distribution entries to surface per field

# Each source's expected dominant language. Drives the language-sanity
# anomaly check.
EXPECTED_LANGUAGES: dict[str, set[str]] = {
    "sigma":               {"sigma"},
    # Elastic rules can be query (kql/kuery/lucene), eql, esql, ml
    # (Machine Learning jobs), threat_match, threshold, new_terms.
    "elastic":             {"eql", "esql", "kql", "kuery", "lucene", "ml", "threat_match", "threshold", "new_terms"},
    # `osquery` is the canonical token for Elastic OSQuery Manager hunts
    # (raw TOML carries language=["SQL"]; normalizer maps to `osquery`).
    "elastic_hunting":     {"esql", "eql", "kql", "lucene", "osquery"},
    "elastic_protections": {"eql"},
    "splunk":              {"spl"},
    "sublime":             {"mql"},
    "lolrmm":              {"sigma"},
    "sentinel":            {"kql"},
    "google_secops":       {"yaral"},
}

# Sources where "no MITRE techniques" is expected behaviour, not a bug.
# Sublime rules are email-security and rarely carry MITRE mapping;
# LOLRMM is RMM-tool detection which DOES map but historically may miss
# on some. Suppresses the no-MITRE anomaly for these.
NON_MITRE_SOURCES: set[str] = {"sublime"}

SOURCES = list(EXPECTED_LANGUAGES.keys())


# ── Data shapes ────────────────────────────────────────────────────


@dataclass
class FieldStats:
    """Distribution of values in a list-valued column."""
    top: list[tuple[str, int]] = field(default_factory=list)
    total_values: int = 0  # sum of list lengths across all rules
    rules_with_only_unknown: int = 0  # column value is exactly ["unknown"]


@dataclass
class SourceAudit:
    source: str
    rule_count: int = 0

    platforms: FieldStats = field(default_factory=FieldStats)
    data_sources: FieldStats = field(default_factory=FieldStats)
    event_types: FieldStats = field(default_factory=FieldStats)

    # Specific anomaly counters
    cross_platform_rules: int = 0       # taxonomy_platforms contains 'cross_platform'
    no_observables_rules: int = 0       # every extracted_* is empty
    no_mitre_rules: int = 0             # mitre_techniques is empty
    canonical_legacy_disagreement: int = 0  # platform not in taxonomy_platforms

    languages: list[tuple[str, int]] = field(default_factory=list)
    unexpected_languages: list[tuple[str, int]] = field(default_factory=list)

    anomalies: list[str] = field(default_factory=list)


# ── Helpers ────────────────────────────────────────────────────────


def pct(num: int, denom: int) -> float:
    return (100.0 * num / denom) if denom else 0.0


def fetch_page(api_base: str, source: str, offset: int) -> dict:
    """One paginated API call. Returns the parsed JSON dict."""
    q = urllib.parse.urlencode({
        "sources": source,
        "limit": PAGE_SIZE,
        "offset": offset,
    })
    url = f"{api_base}/detections?{q}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read())


def fetch_all_rules(api_base: str, source: str) -> Iterable[dict]:
    """Paginate through every rule for `source`. Yields rule dicts."""
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


def stat_list_field(values_per_rule: list[list[str]]) -> FieldStats:
    """Aggregate distribution stats for a list-valued taxonomy column."""
    counter: Counter[str] = Counter()
    only_unknown = 0
    total_values = 0
    for vals in values_per_rule:
        if not vals:
            continue
        total_values += len(vals)
        for v in vals:
            counter[v] += 1
        if vals == ["unknown"]:
            only_unknown += 1
    top = counter.most_common(TOP_N)
    return FieldStats(top=top, total_values=total_values, rules_with_only_unknown=only_unknown)


def has_any_observables(rule: dict) -> bool:
    """True if any extracted_* list-valued field has at least one entry."""
    extracted_fields = (
        "extracted_fields_used", "extracted_event_ids",
        "extracted_process_names", "extracted_file_paths",
        "extracted_registry_keys", "extracted_network_indicators",
        "extracted_source_tables", "extracted_api_actions",
        "extracted_target_resources",
    )
    return any(rule.get(f) for f in extracted_fields)


# ── Audit per source ───────────────────────────────────────────────


def audit_source(api_base: str, source: str) -> SourceAudit:
    audit = SourceAudit(source=source)

    platforms_per_rule: list[list[str]] = []
    data_sources_per_rule: list[list[str]] = []
    event_types_per_rule: list[list[str]] = []
    languages = Counter()

    for rule in fetch_all_rules(api_base, source):
        audit.rule_count += 1

        platforms = rule.get("taxonomy_platforms") or []
        data_sources = rule.get("taxonomy_data_sources") or []
        event_types = rule.get("taxonomy_event_types") or []

        platforms_per_rule.append(platforms)
        data_sources_per_rule.append(data_sources)
        event_types_per_rule.append(event_types)

        if "cross_platform" in platforms:
            audit.cross_platform_rules += 1

        if not has_any_observables(rule):
            audit.no_observables_rules += 1

        if not (rule.get("mitre_techniques") or []):
            audit.no_mitre_rules += 1

        legacy_platform = (rule.get("platform") or "").strip().lower()
        if legacy_platform and legacy_platform not in platforms:
            audit.canonical_legacy_disagreement += 1

        languages[rule.get("language") or "unknown"] += 1

    audit.platforms = stat_list_field(platforms_per_rule)
    audit.data_sources = stat_list_field(data_sources_per_rule)
    audit.event_types = stat_list_field(event_types_per_rule)

    audit.languages = languages.most_common()
    expected = EXPECTED_LANGUAGES.get(source, set())
    audit.unexpected_languages = [
        (lang, n) for lang, n in audit.languages if lang not in expected
    ]

    # ── Anomaly heuristics ──────────────────────────────────────────
    if audit.rule_count:
        unk_pct = pct(audit.platforms.rules_with_only_unknown, audit.rule_count)
        if unk_pct > 5:
            audit.anomalies.append(
                f"taxonomy_platforms == ['unknown'] for {unk_pct:.1f}% of rules "
                f"({audit.platforms.rules_with_only_unknown}/{audit.rule_count}) "
                "-- taxonomy mapping gap"
            )
        cp_pct = pct(audit.cross_platform_rules, audit.rule_count)
        if cp_pct > 5:
            audit.anomalies.append(
                f"taxonomy_platforms contains 'cross_platform' for {cp_pct:.1f}% "
                f"({audit.cross_platform_rules}/{audit.rule_count}) "
                "-- likely an over-broad fallback hiding resolver gaps"
            )
        obs_pct = pct(audit.no_observables_rules, audit.rule_count)
        if obs_pct > 30:
            audit.anomalies.append(
                f"no extracted observables for {obs_pct:.1f}% "
                f"({audit.no_observables_rules}/{audit.rule_count}) "
                "-- parser/extractor coverage gap"
            )
        mitre_pct = pct(audit.no_mitre_rules, audit.rule_count)
        if mitre_pct > 30 and source not in NON_MITRE_SOURCES:
            audit.anomalies.append(
                f"no MITRE techniques for {mitre_pct:.1f}% "
                f"({audit.no_mitre_rules}/{audit.rule_count}) "
                "-- MITRE mapping gap"
            )
        legacy_pct = pct(audit.canonical_legacy_disagreement, audit.rule_count)
        if legacy_pct > 10:
            audit.anomalies.append(
                f"legacy `platform` disagrees with `taxonomy_platforms` for "
                f"{legacy_pct:.1f}% ({audit.canonical_legacy_disagreement}/"
                f"{audit.rule_count}) "
                "-- Phase 3 legacy-removal will surface this discrepancy"
            )
        if audit.unexpected_languages:
            top_unexpected = audit.unexpected_languages[0]
            audit.anomalies.append(
                f"unexpected language: {top_unexpected[0]!r} appears in "
                f"{top_unexpected[1]} rules but isn't in this source's "
                f"expected set {sorted(expected)}"
            )

    return audit


# ── Rendering ──────────────────────────────────────────────────────


def render_text(audit: SourceAudit) -> str:
    out: list[str] = [f"=== {audit.source} ===", f"  rules: {audit.rule_count}"]
    if not audit.rule_count:
        out.append("  (no rules -- skipping distribution stats)")
        return "\n".join(out)

    # Headline rates
    def rate(num: int, label: str) -> str:
        return f"{num:>5} ({pct(num, audit.rule_count):>5.1f}%) {label}"

    out.append(f"  {rate(audit.cross_platform_rules, 'rules tagged cross_platform')}")
    out.append(f"  {rate(audit.platforms.rules_with_only_unknown, 'rules taxonomy_platforms == [unknown]')}")
    out.append(f"  {rate(audit.no_observables_rules, 'rules with NO extracted observables')}")
    out.append(f"  {rate(audit.no_mitre_rules, 'rules with NO MITRE techniques')}")
    out.append(f"  {rate(audit.canonical_legacy_disagreement, 'rules where legacy platform != taxonomy_platforms')}")

    # Top distributions
    for label, st in (
        ("taxonomy_platforms", audit.platforms),
        ("taxonomy_data_sources", audit.data_sources),
        ("taxonomy_event_types", audit.event_types),
    ):
        out.append(f"  top {label}:")
        for value, count in st.top:
            out.append(f"    {count:>5} ({pct(count, audit.rule_count):>5.1f}%) {value}")

    # Languages
    out.append("  languages:")
    for lang, count in audit.languages:
        marker = "" if lang in EXPECTED_LANGUAGES.get(audit.source, set()) else "  <-- unexpected"
        out.append(f"    {count:>5} ({pct(count, audit.rule_count):>5.1f}%) {lang}{marker}")

    if audit.anomalies:
        out.append("  ANOMALIES:")
        for a in audit.anomalies:
            out.append(f"    - {a}")
    return "\n".join(out)


def render_summary(audits: list[SourceAudit]) -> str:
    lines = ["=" * 60, "SUMMARY (ranked by anomaly count)"]
    ranked = sorted(audits, key=lambda a: -len(a.anomalies))
    for a in ranked:
        marker = "clean" if not a.anomalies else f"{len(a.anomalies)} anomalies"
        lines.append(
            f"  {a.source:22s} rules={a.rule_count:>5} "
            f"cross_platform={pct(a.cross_platform_rules, a.rule_count):>5.1f}%  "
            f"unknown={pct(a.platforms.rules_with_only_unknown, a.rule_count):>5.1f}%  "
            f"[{marker}]"
        )
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(
        description="Normalization audit for the Detection Explorer catalog."
    )
    p.add_argument("--source", help="Run only for one source by name.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument(
        "--api",
        default=PROD_API,
        help=f"API base (default: {PROD_API}).",
    )
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
        sys.stdout.write(json.dumps([asdict(a) for a in audits], indent=2) + "\n")
    else:
        sys.stdout.write(render_summary(audits) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
