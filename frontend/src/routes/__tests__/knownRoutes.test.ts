/** The middleware's route table must cover every <Route path> in
 * App.tsx (read from source, so a new page cannot silently 404 at the
 * edge) and reject paths no page renders. */
import { describe, it, expect } from 'vitest';
// Vite's ?raw import: the source text, not the module (typed by vite/client).
import appSource from '../../App.tsx?raw';
import { isKnownRoute } from '../knownRoutes';

const routePaths = [...appSource.matchAll(/<Route path="([^"]+)"/g)]
  .map((m) => m[1])
  .filter((p) => p !== '*');

/** A concrete URL for a react-router path pattern: params and splats filled. */
function sampleFor(pattern: string): string {
  return pattern.replace(/:[A-Za-z]+/g, 'sample-1').replace(/\/\*$/, '/deep/er/path');
}

describe('isKnownRoute', () => {
  it('reads a non-trivial route table out of App.tsx', () => {
    expect(routePaths.length).toBeGreaterThan(15);
    expect(routePaths).toContain('/detections/:id');
    expect(routePaths).toContain('/observables/:kind/*');
  });

  it.each(routePaths)('covers App.tsx route %s', (pattern) => {
    expect(isKnownRoute(sampleFor(pattern))).toBe(true);
  });

  it('ignores a trailing slash', () => {
    expect(isKnownRoute('/detections/')).toBe(true);
    expect(isKnownRoute('/about/')).toBe(true);
    expect(isKnownRoute('/')).toBe(true);
  });

  it.each([
    '/nonexistent-page-xyz',
    '/detections/a/b',
    '/mitre/T1059/extra',
    '/actors/G0016/rules',
    '/methodology/nope',
    '/compare/nope',
    '/query/extra',
    '/digest/2026-w37/x',
    '/intel/anything',
  ])('rejects %s', (path) => {
    expect(isKnownRoute(path)).toBe(false);
  });
});
