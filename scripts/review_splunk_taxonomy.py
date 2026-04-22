"""Spot-check helper for the Splunk taxonomy.

Walks all `splunk` detections, groups by top-level rule folder, and
prints 10 sample rules per folder with:
  - file path (folder + filename)
  - data_source field (Splunk's structured labels)
  - search-query head (first 200 chars — has `index=`, `sourcetype=`,
    `datamodel=` references)
  - current normalized taxonomy (platforms / data_sources / event_types)

Used to eyeball whether our mapping is reasonable and identify gaps.
"""

from __future__ import annotations

import json
import random
import re
import sys
import urllib.request
from collections import defaultdict

API = "https://threat-detection-explorer-production.up.railway.app/api"


def fetch_all_splunk() -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{API}/detections?sources=splunk&limit=200&offset={offset}&sort_by=title"
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
        chunk = [r for r in data.get("items", []) if r.get("source") == "splunk"]
        if not chunk:
            break
        items.extend(chunk)
        offset += 200
        if offset >= data.get("total", 0):
            break
    return items


def folder_of(source_file: str) -> str:
    parts = source_file.replace("\\", "/").split("/")
    # detections/<folder>/...
    if len(parts) >= 2 and parts[0] == "detections":
        return parts[1]
    return "(unknown)"


# Quick extractor for common Splunk signals embedded in the search.
_SIGNAL_PATTERNS = [
    re.compile(r"\bindex\s*=\s*([\w\-\*\"]+)", re.IGNORECASE),
    re.compile(r"\bsourcetype\s*=\s*([\w\-:\*\"]+)", re.IGNORECASE),
    re.compile(r"\bdatamodel\s*=\s*([\w\-\.]+)", re.IGNORECASE),
    re.compile(r"\|\s*tstats\b.*?\bfrom\s+datamodel\s*=\s*([\w\-\.]+)", re.IGNORECASE),
    re.compile(r"source\s*=\s*\"?([\w\-:\*\.]+)", re.IGNORECASE),
]


def extract_signals(query: str) -> list[str]:
    """Pull index / sourcetype / datamodel / source tokens out of the query."""
    if not query:
        return []
    out: list[str] = []
    for pat in _SIGNAL_PATTERNS:
        for m in pat.finditer(query):
            val = m.group(1).strip().strip('"').strip("'").lower()
            if val and val not in out:
                out.append(val)
    return out


def main() -> int:
    random.seed(42)
    rules = fetch_all_splunk()
    by_folder: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_folder[folder_of(r["source_file"])].append(r)

    print(f"Total splunk rules: {len(rules)}")
    print(f"Top-level folders: {len(by_folder)}")
    print()

    for folder, items in sorted(by_folder.items(), key=lambda kv: -len(kv[1])):
        print(f"== {folder} ({len(items)} rules) ==")
        sample = random.sample(items, min(10, len(items)))
        for r in sample:
            query = (r.get("detection_logic") or "")[:400].replace("\n", " ").replace("  ", " ")
            signals = extract_signals(r.get("detection_logic") or "")
            print(f"  [{r['rule_id'] or r['id'][:8]}] {r['title'][:80]}")
            print(f"    file:     {r['source_file']}")
            print(f"    query:    {query[:300]}")
            print(f"    signals:  {signals[:8]}")
            print(f"    platforms:    {r['taxonomy_platforms']}")
            print(f"    data_sources: {r['taxonomy_data_sources']}")
            print(f"    event_types:  {r['taxonomy_event_types']}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
