/**
 * Stale-chunk recovery. Each deploy renames the hashed JS/CSS chunks;
 * a tab opened before the deploy then 404s when a lazy route's chunk
 * is first fetched. Without handling, the dynamic import rejects, the
 * render tree unmounts, and the user stares at a blank page until they
 * refresh by hand. Recovery = one automatic reload to pick up the new
 * asset manifest, rate-limited so a genuinely broken deploy degrades
 * to the visible error screen instead of a reload loop.
 */

const KEY = 'tde-chunk-reload-at';
const MIN_INTERVAL_MS = 60_000;

export function isChunkLoadError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err ?? '');
  // Chromium: "Failed to fetch dynamically imported module: ..."
  // Firefox:  "error loading dynamically imported module"
  // Safari:   "Importing a module script failed."
  // Vite CSS preload: "Unable to preload CSS for ..."
  return /dynamically imported module|module script failed|preload CSS|Loading chunk/i.test(msg);
}

/** Reload the page to fetch the fresh deploy, at most once a minute.
 * Returns false when a recent reload already failed to fix it. */
export function reloadForStaleChunk(): boolean {
  let last = 0;
  try {
    last = Number(sessionStorage.getItem(KEY) || 0);
  } catch {
    // Storage unavailable (private mode etc.) — still reload once per
    // in-memory flag so we don't loop within this document.
    if (reloadedThisDocument) return false;
  }
  if (Date.now() - last < MIN_INTERVAL_MS) return false;
  try {
    sessionStorage.setItem(KEY, String(Date.now()));
  } catch {
    /* ignore */
  }
  reloadedThisDocument = true;
  window.location.reload();
  return true;
}

let reloadedThisDocument = false;
