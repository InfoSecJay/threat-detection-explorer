/** The SPA's route table, for the edge middleware (#160, DX-18).
 *
 * Vercel's catch-all rewrite serves index.html with a 200 for every
 * URL, so crawlers index soft 404s. The middleware answers anything
 * outside this table with the same shell and a real 404 status. The
 * patterns mirror App.tsx; knownRoutes.test.ts reads App.tsx and
 * asserts every <Route path> is covered, so the two cannot drift.
 *
 * Deliberately generous inside a route family: /detections/<id> is
 * "known" whether or not the id exists (the prerender endpoints give
 * bots a real 404 for a missing id; humans get the in-app not-found
 * state). The table only needs to reject paths no page can render. */

const ONE = '[^/]+';

export const KNOWN_ROUTES: readonly RegExp[] = [
  /^\/$/,
  new RegExp(`^/detections(/${ONE})?$`),
  new RegExp(`^/mitre(/${ONE})?$`),
  new RegExp(`^/actors(/${ONE})?$`),
  /^\/query$/,
  /^\/compare(\/(mitre-coverage|side-by-side))?$/,
  /^\/intel$/,
  /^\/about$/,
  /^\/methodology(\/(unclassified|corpus-health))?$/,
  /^\/integrations$/,
  new RegExp(`^/digest(/${ONE})?$`),
  new RegExp(`^/observables(/${ONE}(/.*)?)?$`),
];

/** True when the SPA has a route for `pathname` (trailing slashes ignored). */
export function isKnownRoute(pathname: string): boolean {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  return KNOWN_ROUTES.some((re) => re.test(path));
}
