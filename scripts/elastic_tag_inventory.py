"""Inventory Data Source / OS / Domain tags across the Elastic corpus.

Walks all `elastic` detections and counts distinct tag values in the
`Data Source: *`, `OS: *`, and `Domain: *` namespaces. The output is
the authoritative source-of-truth list that the taxonomy mapping
(elastic.yaml → tags section) needs to cover.

Run against prod:

    python scripts/elastic_tag_inventory.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from collections import Counter

API = "https://threat-detection-explorer-production.up.railway.app/api"


def fetch_all_elastic() -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        url = f"{API}/detections?sources=elastic&limit=200&offset={offset}"
        with urllib.request.urlopen(url) as r:
            data = json.load(r)
        chunk = [r for r in data.get("items", []) if r.get("source") == "elastic"]
        if not chunk:
            break
        items.extend(chunk)
        offset += 200
        if offset >= data.get("total", 0):
            break
    return items


def main() -> int:
    rules = fetch_all_elastic()
    print(f"Inspected {len(rules)} elastic rules\n")

    buckets: dict[str, Counter] = {
        "OS": Counter(),
        "Data Source": Counter(),
        "Domain": Counter(),
        "Rule Type": Counter(),
    }

    for r in rules:
        for tag in r.get("tags") or []:
            if not isinstance(tag, str) or ":" not in tag:
                continue
            prefix, _, value = tag.partition(":")
            prefix = prefix.strip()
            value = value.strip()
            if prefix in buckets and value:
                buckets[prefix][value] += 1

    for label, counter in buckets.items():
        print(f"== {label} tags ({len(counter)} distinct values) ==")
        for value, count in counter.most_common():
            print(f"  {count:4d}  {value}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
