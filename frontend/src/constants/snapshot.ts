/**
 * Headline numbers baked into the bundle at build time (#82 S2.7).
 *
 * `vite.config.ts` fetches them from the production API during
 * `vite build` and injects them via `define`; in dev and tests the
 * value is null. Consumers use these ONLY while the live query has no
 * data yet, so the first paint shows a real recent number instead of a
 * dash and the live value takes over as soon as it lands. Never treat
 * them as current: the corpus moves nightly, the bundle moves on deploy.
 */

export interface BakedSnapshot {
  rules: number;
  coverage: { covered: number; total: number; percent: number };
  last_sync: string | null;
  /** ISO timestamp of the build that produced these numbers. */
  baked_at: string;
}

function isSnapshot(v: unknown): v is BakedSnapshot {
  if (!v || typeof v !== 'object') return false;
  const s = v as Record<string, unknown>;
  const c = s.coverage as Record<string, unknown> | undefined;
  return (
    typeof s.rules === 'number' &&
    !!c && typeof c.covered === 'number' && typeof c.total === 'number' && typeof c.percent === 'number' &&
    typeof s.baked_at === 'string'
  );
}

export const BAKED_SNAPSHOT: BakedSnapshot | null =
  typeof __DE_SNAPSHOT__ !== 'undefined' && isSnapshot(__DE_SNAPSHOT__) ? __DE_SNAPSHOT__ : null;
