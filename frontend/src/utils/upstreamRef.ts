/** The git ref a GitHub blob URL points at (DX-15 / #157).
 *
 * `source_rule_url` is pinned to the commit the catalog indexed
 * (`/blob/<40-hex sha>/`); rows from before DX-15 still carry a branch
 * (`/blob/main/`) until the next sync. The rule page labels the link
 * differently in each case and only offers a "latest on <branch>" link
 * when there is a pinned one to contrast it with. */
export function upstreamRef(url: string | null | undefined): { ref: string; pinned: boolean } | null {
  const m = /\/blob\/([^/]+)\//.exec(url || '');
  if (!m) return null;
  return { ref: m[1], pinned: /^[0-9a-f]{40}$/.test(m[1]) };
}
