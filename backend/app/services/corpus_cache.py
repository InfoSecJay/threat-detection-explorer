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

import functools
import json
import logging
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Hashable

logger = logging.getLogger(__name__)

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.utils.datetime_utils import utcnow

Fingerprint = tuple[int, str]

_MISS = object()  # sentinel: artifact table had no usable row


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
        self,
        db: AsyncSession,
        key: Hashable,
        compute: Callable[[], Awaitable[Any]],
        persist: bool = False,
    ) -> Any:
        """Fingerprint-keyed memo.

        With `persist=True` (#81 / teardown S2.4) the value is also
        written to the computed_artifacts table, so the NEXT process
        (every deploy empties the in-process cache) finds it at the
        same fingerprint and serves warm instead of rescanning.
        Persistence is strictly best-effort: unserializable values and
        DB hiccups fall back to compute.
        """
        fp = await self.fingerprint(db)
        if fp != self._fingerprint:
            self._entries.clear()
            self._fingerprint = fp
        if key in self._entries:
            self.hits += 1
            self._entries.move_to_end(key)
            return self._entries[key]

        if persist:
            stored = await self._load_artifact(db, key, fp)
            if stored is not _MISS:
                self.hits += 1
                self._remember(key, stored)
                return stored

        self.misses += 1
        value = await compute()
        self._remember(key, value)
        if persist:
            await self._store_artifact(db, key, fp, value)
        return value

    def _remember(self, key: Hashable, value: Any) -> None:
        self._entries[key] = value
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    async def _load_artifact(self, db: AsyncSession, key: Hashable, fp: Fingerprint) -> Any:
        from app.models.computed_artifact import ComputedArtifact

        try:
            row = await db.get(ComputedArtifact, repr(key)[:400])
        except Exception as e:  # noqa: BLE001 -- table missing, connection blip
            logger.debug(f"artifact load failed for {key!r}: {e}")
            return _MISS
        if row is not None and row.fingerprint == repr(fp):
            return row.payload
        return _MISS

    async def _store_artifact(self, db: AsyncSession, key: Hashable, fp: Fingerprint, value: Any) -> None:
        from app.models.computed_artifact import ComputedArtifact

        try:
            json.dumps(value)  # only JSON-shaped values persist
        except (TypeError, ValueError):
            return
        try:
            await db.merge(ComputedArtifact(
                key=repr(key)[:400], fingerprint=repr(fp), payload=value,
            ))
            await db.commit()
        except Exception as e:  # noqa: BLE001 -- persistence is best-effort
            logger.warning(f"artifact store failed for {key!r}: {e}")
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass

    def stats(self) -> dict:
        return {
            "entries": len(self._entries),
            "hits": self.hits,
            "misses": self.misses,
            "fingerprint": self._fingerprint,
        }


corpus_cache = CorpusCache()


def memoised(name: str, daily: bool = True):
    """Route decorator: memoise an async FastAPI handler's result on the
    corpus fingerprint, keyed by its query parameters (and the UTC date
    when `daily`, for windows anchored to "now"). The handler must take
    the session as a `db` keyword (the `Depends(get_db)` convention);
    without one the call passes straight through.
    """
    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            # The session may arrive as the `db` keyword or positionally,
            # depending on how the framework resolved the dependency.
            db = kwargs.get("db")
            if db is None:
                db = next((a for a in list(args) + list(kwargs.values()) if isinstance(a, AsyncSession)), None)
            if db is None:
                return await fn(*args, **kwargs)
            params = (
                tuple(repr(a) for a in args if not isinstance(a, AsyncSession)),
                tuple(sorted((k, repr(v)) for k, v in kwargs.items() if not isinstance(v, AsyncSession))),
            )
            key = (name, params, utcnow().date().isoformat() if daily else None)
            return await corpus_cache.get(db, key, lambda: fn(*args, **kwargs))
        return wrapper
    return deco
