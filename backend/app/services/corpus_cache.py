"""Corpus-stamped memo for read-mostly aggregates.

The detections table only changes when the sync worker runs (nightly,
plus manual triggers), yet the sidebar facets, statistics and filter
options are recomputed from a full scan on every catalog page view.
This cache keys each computed value on a corpus fingerprint --
COUNT(*) and MAX(updated_at) -- so a hit costs one tiny query instead
of a 12k-row scan, and any ingest (new rows, changed rows, stale-row
cleanup) invalidates everything at once.

The API and the worker are separate processes; the API sees a new
fingerprint on its next request after the worker commits, so nothing
has to be signalled between them.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Awaitable, Callable, Hashable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection

Fingerprint = tuple[int, str]


class CorpusCache:
    """Fingerprint-keyed memo with a bounded number of entries.

    Entries are dropped wholesale when the fingerprint moves, and the
    least-recently-used entry is evicted past `max_entries` so
    free-text facet queries cannot grow the cache without bound.
    """

    def __init__(self, max_entries: int = 512) -> None:
        self.max_entries = max_entries
        self._fingerprint: Fingerprint | None = None
        self._entries: OrderedDict[Hashable, Any] = OrderedDict()
        self.hits = 0
        self.misses = 0

    async def fingerprint(self, db: AsyncSession) -> Fingerprint:
        row = (
            await db.execute(select(func.count(Detection.id), func.max(Detection.updated_at)))
        ).one()
        return (int(row[0] or 0), str(row[1]))

    def invalidate(self) -> None:
        self._fingerprint = None
        self._entries.clear()

    async def get(
        self, db: AsyncSession, key: Hashable, compute: Callable[[], Awaitable[Any]]
    ) -> Any:
        fp = await self.fingerprint(db)
        if fp != self._fingerprint:
            self._entries.clear()
            self._fingerprint = fp
        if key in self._entries:
            self.hits += 1
            self._entries.move_to_end(key)
            return self._entries[key]
        self.misses += 1
        value = await compute()
        self._entries[key] = value
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return value

    def stats(self) -> dict:
        return {
            "entries": len(self._entries),
            "hits": self.hits,
            "misses": self.misses,
            "fingerprint": self._fingerprint,
        }


corpus_cache = CorpusCache()
