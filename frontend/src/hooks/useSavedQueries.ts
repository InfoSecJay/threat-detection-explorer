/**
 * Recent + starred search queries, persisted in localStorage (#14).
 *
 * Recents are recorded on every non-empty submit (deduped, newest
 * first, capped). Starring promotes a query out of recents into the
 * named saved list. No server side — sharing already works via the
 * URL (`/detections?q=…`), and server-side saving would need auth we
 * don't have.
 */

import { useCallback, useEffect, useState } from 'react';

export interface RecentQuery {
  query: string;
  ts: number;
}

export interface SavedQuery {
  query: string;
  name: string;
  ts: number;
}

const RECENT_KEY = 'tde.search.recent';
const SAVED_KEY = 'tde.search.saved';
const RECENT_CAP = 8;

function read<T>(key: string): T[] {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function write(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Quota / private browsing — degrade silently, it's a nicety.
  }
}

export function useSavedQueries() {
  const [recent, setRecent] = useState<RecentQuery[]>(() => read(RECENT_KEY));
  const [saved, setSaved] = useState<SavedQuery[]>(() => read(SAVED_KEY));

  // Cross-tab sync: another tab writing the keys updates this one.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === RECENT_KEY) setRecent(read(RECENT_KEY));
      if (e.key === SAVED_KEY) setSaved(read(SAVED_KEY));
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const persistRecent = useCallback((next: RecentQuery[]) => {
    setRecent(next);
    write(RECENT_KEY, next);
  }, []);

  const recordRecent = useCallback(
    (query: string) => {
      const q = query.trim();
      if (!q) return;
      setRecent((prev) => {
        const next = [
          { query: q, ts: Date.now() },
          ...prev.filter((r) => r.query !== q),
        ].slice(0, RECENT_CAP);
        write(RECENT_KEY, next);
        return next;
      });
    },
    [],
  );

  const star = useCallback(
    (query: string, name?: string) => {
      const q = query.trim();
      if (!q) return;
      setSaved((prev) => {
        if (prev.some((s) => s.query === q)) return prev;
        const next = [{ query: q, name: name?.trim() || q, ts: Date.now() }, ...prev];
        write(SAVED_KEY, next);
        return next;
      });
      // Promoted out of recents.
      setRecent((prev) => {
        const next = prev.filter((r) => r.query !== q);
        write(RECENT_KEY, next);
        return next;
      });
    },
    [],
  );

  const unstar = useCallback((query: string) => {
    setSaved((prev) => {
      const next = prev.filter((s) => s.query !== query);
      write(SAVED_KEY, next);
      return next;
    });
  }, []);

  const rename = useCallback((query: string, name: string) => {
    const n = name.trim();
    if (!n) return;
    setSaved((prev) => {
      const next = prev.map((s) => (s.query === query ? { ...s, name: n } : s));
      write(SAVED_KEY, next);
      return next;
    });
  }, []);

  const clearRecent = useCallback(() => persistRecent([]), [persistRecent]);

  return { recent, saved, recordRecent, star, unstar, rename, clearRecent };
}
