"""One-shot cleanup for issue #7.

Reads DATABASE_URL from env, verifies the stale okta_custom_detections
row still matches expectations (0 rules, name match, single hit), then
deletes it. Refuses to proceed if the row shape has changed.

Run: env DATABASE_URL="postgresql://..." python cleanup_okta_row.py
"""
import asyncio
import os
import sys

import asyncpg


TARGET_NAME = "okta_custom_detections"


async def main() -> int:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL not set", file=sys.stderr)
        return 2

    conn = await asyncpg.connect(url)
    try:
        rows = await conn.fetch(
            "SELECT id, name, rule_count, last_sync_at FROM repositories WHERE name = $1",
            TARGET_NAME,
        )
        print(f"SELECT matched {len(rows)} row(s):")
        for r in rows:
            print(f"  id={r['id']}  name={r['name']}  rule_count={r['rule_count']}  last_sync_at={r['last_sync_at']}")

        if len(rows) == 0:
            print("Nothing to delete — row is already gone.")
            return 0
        if len(rows) > 1:
            print(f"REFUSING: expected exactly 1 row, got {len(rows)}. Manual investigation required.")
            return 3
        row = rows[0]
        if row["rule_count"] != 0:
            print(f"REFUSING: expected rule_count=0, got {row['rule_count']}. Row has content — not safe to delete.")
            return 4

        print("\nDeleting...")
        result = await conn.execute(
            "DELETE FROM repositories WHERE name = $1 AND rule_count = 0",
            TARGET_NAME,
        )
        print(f"Result: {result}")

        # Verify
        remaining = await conn.fetchval(
            "SELECT COUNT(*) FROM repositories WHERE name = $1", TARGET_NAME
        )
        print(f"Rows matching '{TARGET_NAME}' after delete: {remaining}")
        return 0 if remaining == 0 else 5
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
