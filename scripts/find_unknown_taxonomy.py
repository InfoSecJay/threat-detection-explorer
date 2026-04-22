"""Find all detections with any taxonomy field == [unknown].

Walks every detection across all sources and prints rules whose
`taxonomy_platforms`, `taxonomy_data_sources`, or `taxonomy_event_types`
is exactly `["unknown"]`. Groups by source so the output is easy to
scan, and shows enough context to figure out why the rule missed.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from collections import defaultdict

API = "https://threat-detection-explorer-production.up.railway.app/api"


def fetch_all() -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{API}/detections?limit=200&offset={offset}&sort_by=title"
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
        chunk = data.get("items", [])
        if not chunk:
            break
        items.extend(chunk)
        total = data.get("total", 0)
        offset += 200
        if offset >= total:
            break
    return items


def is_unknown(values) -> bool:
    return values == ["unknown"] or (isinstance(values, list) and len(values) == 1 and values[0] == "unknown")


def main() -> int:
    rules = fetch_all()
    print(f"Fetched {len(rules)} total rules\n")

    by_source: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        # A rule "has an unknown field" if ANY of the three dims is [unknown]
        p = r.get("taxonomy_platforms") or []
        d = r.get("taxonomy_data_sources") or []
        e = r.get("taxonomy_event_types") or []
        if is_unknown(p) or is_unknown(d) or is_unknown(e):
            by_source[r["source"]].append(r)

    total = sum(len(v) for v in by_source.values())
    print(f"Total rules with at least one unknown dimension: {total}\n")

    for source in sorted(by_source, key=lambda s: -len(by_source[s])):
        items = by_source[source]
        print(f"== {source} ({len(items)} rules) ==")
        for r in items[:40]:  # cap per-source output
            p = r.get("taxonomy_platforms") or []
            d = r.get("taxonomy_data_sources") or []
            e = r.get("taxonomy_event_types") or []
            # Flag which dims are unknown
            flags = []
            if is_unknown(p):
                flags.append("P")
            if is_unknown(d):
                flags.append("D")
            if is_unknown(e):
                flags.append("E")
            flag_str = "".join(flags)
            query = (r.get("detection_logic") or "").replace("\n", " ")
            print(f"  [{flag_str}] {r['rule_id'] or r['id'][:8]}: {r['title'][:80]}")
            print(f"       file:    {r['source_file']}")
            print(f"       query:   {query[:180]}")
            print(f"       P={p}  D={d}  E={e}")
        if len(items) > 40:
            print(f"  ... and {len(items) - 40} more")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
