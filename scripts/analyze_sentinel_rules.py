"""Inventory Sentinel rule structure for taxonomy analysis.

Samples every detection and reports:
  - Top-level folder distribution (Solutions/<vendor>/...)
  - Distinct connectorId + dataType pairs
  - Rules with no requiredDataConnectors
  - Entity mapping prevalence
  - Current taxonomy resolution state

Purpose: understand the shape of the corpus so we can design a
better mapping strategy than the current resolver (which only looks
at connectorId + dataType).
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from collections import Counter, defaultdict

API = "https://threat-detection-explorer-production.up.railway.app/api"


def fetch_all_sentinel() -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{API}/detections?sources=sentinel&limit=200&offset={offset}&sort_by=title"
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
        chunk = [r for r in data.get("items", []) if r.get("source") == "sentinel"]
        if not chunk:
            break
        items.extend(chunk)
        offset += 200
        if offset >= data.get("total", 0):
            break
    return items


def solution_name(source_file: str) -> str:
    """Extract `Solutions/<vendor>/...` name."""
    parts = source_file.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "Solutions":
        return parts[1]
    return "(root)"


def analyze() -> int:
    rules = fetch_all_sentinel()
    print(f"Total sentinel rules: {len(rules)}\n")

    # 1. Top Solutions folders
    folder_counts: Counter = Counter()
    for r in rules:
        folder_counts[solution_name(r["source_file"])] += 1
    top_folders = folder_counts.most_common(30)
    print(f"== Top 30 Solutions folders (of {len(folder_counts)} total) ==")
    for name, count in top_folders:
        print(f"  {count:4d}  {name}")
    print()

    # 2. Taxonomy state per folder
    print("== Coverage per top folder ==")
    by_folder: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "unknown_P": 0, "unknown_D": 0, "unknown_E": 0, "all_unknown": 0}
    )
    for r in rules:
        f = solution_name(r["source_file"])
        bucket = by_folder[f]
        bucket["total"] += 1
        p = r.get("taxonomy_platforms") or []
        d = r.get("taxonomy_data_sources") or []
        e = r.get("taxonomy_event_types") or []
        if p == ["unknown"]:
            bucket["unknown_P"] += 1
        if d == ["unknown"]:
            bucket["unknown_D"] += 1
        if e == ["unknown"]:
            bucket["unknown_E"] += 1
        if p == ["unknown"] and d == ["unknown"] and e == ["unknown"]:
            bucket["all_unknown"] += 1

    print(f"{'folder':45s} {'total':>6} {'uP':>5} {'uD':>5} {'uE':>5} {'all-unk':>7}")
    for name, _ in top_folders[:20]:
        b = by_folder[name]
        print(
            f"{name[:45]:45s} {b['total']:>6} {b['unknown_P']:>5} "
            f"{b['unknown_D']:>5} {b['unknown_E']:>5} {b['all_unknown']:>7}"
        )
    print()

    # 3. Sample a diverse set of rules to inspect raw_content
    # Pick 2 rules from each of top 15 folders + 10 all-unknown rules
    sample_rules = []
    for name, _ in top_folders[:15]:
        folder_rules = [r for r in rules if solution_name(r["source_file"]) == name]
        sample_rules.extend(folder_rules[:2])
    # Also sample rules with all-unknown taxonomy
    all_unknown = [
        r for r in rules
        if (r.get("taxonomy_platforms") or []) == ["unknown"]
        and (r.get("taxonomy_data_sources") or []) == ["unknown"]
        and (r.get("taxonomy_event_types") or []) == ["unknown"]
    ]
    sample_rules.extend(all_unknown[:10])

    print(f"== Sample of {len(sample_rules)} rules (structure + fields) ==\n")
    for r in sample_rules:
        raw = r.get("raw_content") or ""
        # Extract key fields from raw YAML
        connectors_match = re.search(r"requiredDataConnectors:\s*(.*?)(?=\n\w|\Z)", raw, re.DOTALL)
        connectors = connectors_match.group(1).strip()[:300] if connectors_match else "(none)"
        entity_match = re.search(r"entityMappings:\s*(.*?)(?=\n\w|\Z)", raw, re.DOTALL)
        entities = entity_match.group(1).strip()[:200] if entity_match else "(none)"
        kind_match = re.search(r"^kind:\s*(\S+)", raw, re.MULTILINE)
        kind = kind_match.group(1) if kind_match else "(none)"
        query_snippet = (r.get("detection_logic") or "")[:200].replace("\n", " ")

        p = r.get("taxonomy_platforms") or []
        d = r.get("taxonomy_data_sources") or []
        e = r.get("taxonomy_event_types") or []

        print(f"[{r['rule_id'] or r['id'][:8]}] {r['title'][:80]}")
        print(f"  folder:  {solution_name(r['source_file'])}")
        print(f"  file:    {r['source_file']}")
        print(f"  kind:    {kind}")
        print(f"  P={p}  D={d}  E={e}")
        print(f"  query:   {query_snippet}")
        print(f"  connectors: {connectors}")
        print(f"  entities:   {entities[:100]}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(analyze())
