#!/usr/bin/env python
# Usage (backend venv): DB_URL=<postgres url> python scripts/extraction_pull_samples.py samples.json 80
"""Pull a per-source sample of live rules from production Postgres into a
local JSON file so extractors can be re-run and inspected offline.
Read-only. DB_URL comes from the environment (never printed)."""
import asyncio
import json
import os
import random
import sys

import asyncpg

OUT = sys.argv[1]
PER_SOURCE = int(sys.argv[2]) if len(sys.argv) > 2 else 60
COLS = [
    "id", "source", "language", "title", "source_file", "detection_logic", "raw_content",
    "platforms", "data_sources", "event_types",
    "extracted_fields_used", "extracted_event_ids", "extracted_process_names",
    "extracted_file_paths", "extracted_registry_keys", "extracted_network_indicators",
    "extracted_source_tables", "extracted_observables", "extracted_api_actions",
    "extracted_target_resources", "query_complexity",
]


async def main() -> None:
    url = os.environ["DB_URL"].replace("postgres://", "postgresql://")
    conn = await asyncpg.connect(url)
    sources = [r["source"] for r in await conn.fetch("SELECT DISTINCT source FROM detections ORDER BY 1")]
    out = {}
    for src in sources:
        rows = await conn.fetch(
            f"SELECT {', '.join(COLS)} FROM detections WHERE source = $1 ORDER BY random() LIMIT $2",
            src, PER_SOURCE,
        )
        items = []
        for r in rows:
            d = dict(r)
            for k, v in list(d.items()):
                if isinstance(v, str) and k.startswith("extracted_") or k in ("platforms", "data_sources", "event_types"):
                    try:
                        d[k] = json.loads(v) if isinstance(v, str) else v
                    except Exception:
                        pass
            items.append(d)
        out[src] = items
        print(src, len(items), file=sys.stderr)
    await conn.close()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, default=str)


asyncio.run(main())
