"""Spot-check helper for the Elastic taxonomy.

Walks all elastic detections in the DB, groups them by top-level rule
folder (rules/<folder>/...), and prints 3 sample rules per folder with
their normalized taxonomy. Run against prod with:

    python scripts/review_elastic_taxonomy.py

Used to sanity-check whether platform / data_source / event_type look
reasonable given the rule's folder + title. Not automated — the goal
is a human eyeballs the output and flags anything suspicious.
"""

from __future__ import annotations

import json
import random
import sys
import urllib.request
from collections import defaultdict

API = "https://threat-detection-explorer-production.up.railway.app/api"


def fetch_all_elastic() -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{API}/detections?sources=elastic&limit=200&offset={offset}&sort_by=title"
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
        chunk = data.get("items", [])
        if not chunk:
            break
        # Be paranoid about the filter — server-side `sources` should
        # include only `elastic`, but filter client-side too in case.
        chunk = [r for r in chunk if r.get("source") == "elastic"]
        items.extend(chunk)
        offset += 200
        if offset >= data.get("total", 0):
            break
    return items


def folder_of(source_file: str) -> str:
    parts = source_file.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] == "rules":
        return parts[1]
    return "(unknown)"


def main() -> int:
    random.seed(42)
    rules = fetch_all_elastic()

    by_folder: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_folder[folder_of(r["source_file"])].append(r)

    print(f"Total elastic rules: {len(rules)}")
    print(f"Top-level folders: {len(by_folder)}")
    print()
    for folder, items in sorted(by_folder.items(), key=lambda kv: -len(kv[1])):
        print(f"== {folder} ({len(items)} rules) ==")
        sample = random.sample(items, min(3, len(items)))
        for r in sample:
            print(f"  {r['rule_id'] or r['id'][:8]}: {r['title'][:90]}")
            print(f"    file:     {r['source_file']}")
            print(f"    language: {r['language']}")
            print(f"    platforms:    {r['taxonomy_platforms']}")
            print(f"    data_sources: {r['taxonomy_data_sources']}")
            print(f"    event_types:  {r['taxonomy_event_types']}")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
