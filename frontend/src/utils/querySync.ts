/**
 * Bidirectional bar <-> sheet translation (#13).
 *
 * The Lucene bar (`q`) and the filter sheet (array filters) used to be
 * independent surfaces composed via AND at the API. This module makes
 * them read as ONE filter state:
 *
 *  - bar -> sheet: the TRANSLATABLE subset of `q` (a flat, top-level
 *    AND of `field:value` terms) is parsed into tokens; the sheet
 *    renders its checkboxes from array filters UNION bar tokens.
 *  - sheet -> bar: checking a mapped facet writes a `field:value`
 *    token into `q`; unchecking removes the owning token (or the
 *    array entry, whichever surface owns the value).
 *
 * Queries using OR / NOT / grouping / ranges are OPAQUE: they keep
 * filtering exactly as typed, the sheet simply doesn't mirror them,
 * and sheet changes fall back to array filters (compose via AND, the
 * pre-#13 behavior). Partial translation of a boolean expression
 * would silently change its meaning — refusing is the correct move.
 *
 * FIELD_MAP mirrors the backend QUERYABLE_FIELDS registry
 * (app/services/query_parser.py) for the subset with sheet sections.
 * If an alias changes there, update here — the round-trip tests in
 * __tests__/querySync.test.ts are the drift tripwire.
 */

import type { SearchFilters } from '../types';

export interface BarToken {
  /** Sheet filter key this token maps to (null = unmapped field or bare word). */
  key: keyof SearchFilters | null;
  /** Field alias as typed (null for bare words). */
  field: string | null;
  /** Unquoted value. */
  value: string;
  /** Verbatim token text, for lossless removal/rebuild. */
  raw: string;
}

export interface ParsedBar {
  tokens: BarToken[];
  /** True when q uses syntax beyond flat AND-of-terms. */
  opaque: boolean;
}

const FIELD_MAP: { key: keyof SearchFilters; canonical: string; aliases: string[] }[] = [
  { key: 'sources', canonical: 'source', aliases: ['source'] },
  { key: 'severities', canonical: 'severity', aliases: ['sev', 'severity'] },
  { key: 'statuses', canonical: 'status', aliases: ['status'] },
  { key: 'languages', canonical: 'lang', aliases: ['lang', 'language'] },
  { key: 'platforms', canonical: 'platform', aliases: ['platform'] },
  { key: 'data_sources_normalized', canonical: 'data', aliases: ['data', 'datasource'] },
  { key: 'event_categories', canonical: 'event', aliases: ['event', 'eventtype'] },
  { key: 'mitre_tactics', canonical: 'tactic', aliases: ['tactic'] },
  { key: 'mitre_techniques', canonical: 'tech', aliases: ['tech', 'technique'] },
  { key: 'mitre_groups', canonical: 'actor', aliases: ['actor', 'group'] },
  { key: 'mitre_software', canonical: 'software', aliases: ['software', 'tool', 'malware'] },
  { key: 'use_cases', canonical: 'usecase', aliases: ['usecase', 'story', 'use_case'] },
  { key: 'tags', canonical: 'tag', aliases: ['tag'] },
];

const ALIAS_TO_KEY = new Map<string, keyof SearchFilters>(
  FIELD_MAP.flatMap((f) => f.aliases.map((a) => [a, f.key] as [string, keyof SearchFilters])),
);
const KEY_TO_CANONICAL = new Map<keyof SearchFilters, string>(
  FIELD_MAP.map((f) => [f.key, f.canonical]),
);

export const MAPPED_SHEET_KEYS = FIELD_MAP.map((f) => f.key);

/** Split q into whitespace-separated tokens, respecting double quotes
 * (both bare `a:"x y"` values and standalone quoted phrases). */
function splitTokens(q: string): string[] {
  const out: string[] = [];
  let buf = '';
  let inQuote = false;
  for (const ch of q) {
    if (ch === '"') {
      inQuote = !inQuote;
      buf += ch;
      continue;
    }
    if (!inQuote && /\s/.test(ch)) {
      if (buf) out.push(buf);
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (buf) out.push(buf);
  return out;
}

function unquote(v: string): string {
  return v.startsWith('"') && v.endsWith('"') && v.length >= 2
    ? v.slice(1, -1)
    : v;
}

function quoteIfNeeded(v: string): string {
  return /\s/.test(v) ? `"${v}"` : v;
}

export function parseBar(q: string): ParsedBar {
  const trimmed = (q || '').trim();
  if (!trimmed) return { tokens: [], opaque: false };

  // Anything beyond a flat AND of terms is opaque. `-term`, `field:>x`
  // ranges, and grouping all change semantics under partial edits.
  if (/[()[\]{]/.test(trimmed) || /(^|\s)(OR|NOT)(\s|$)/i.test(trimmed) || /(^|\s)-\w/.test(trimmed)) {
    return { tokens: [], opaque: true };
  }

  const tokens: BarToken[] = [];
  for (const raw of splitTokens(trimmed)) {
    if (/^AND$/i.test(raw)) continue; // implicit AND == explicit AND
    const colon = raw.indexOf(':');
    if (colon > 0) {
      const field = raw.slice(0, colon).toLowerCase();
      const value = unquote(raw.slice(colon + 1));
      tokens.push({
        key: ALIAS_TO_KEY.get(field) ?? null,
        field,
        value,
        raw,
      });
    } else {
      tokens.push({ key: null, field: null, value: unquote(raw), raw });
    }
  }
  return { tokens, opaque: false };
}

/** Rebuild q from remaining tokens (implicit AND join). */
function rebuild(tokens: BarToken[]): string {
  return tokens.map((t) => t.raw).join(' ');
}

/** View model: array filters with bar tokens merged in, so the sheet
 * checkboxes and pills reflect BOTH surfaces. */
export function mergeTokensIntoFilters(
  filters: SearchFilters,
  parsed: ParsedBar,
): SearchFilters {
  if (parsed.opaque || parsed.tokens.length === 0) return filters;
  const view: SearchFilters = { ...filters };
  for (const token of parsed.tokens) {
    if (!token.key) continue;
    const existing = (view[token.key] as string[] | undefined) || [];
    if (!existing.some((v) => v.toLowerCase() === token.value.toLowerCase())) {
      (view as Record<string, unknown>)[token.key] = [...existing, token.value];
    }
  }
  return view;
}

/**
 * Translate a sheet/pills edit (made against the VIEW) back onto the
 * real state: additions to mapped keys become bar tokens (or array
 * entries when q is opaque); removals delete from whichever surface
 * owns the value.
 */
export function reconcileFilterChange(
  current: SearchFilters,
  view: SearchFilters,
  next: SearchFilters,
  parsed: ParsedBar,
): SearchFilters {
  const result: SearchFilters = { ...next };
  let tokens = [...parsed.tokens];
  let tokensChanged = false;

  for (const { key } of FIELD_MAP) {
    const viewVals = ((view[key] as string[] | undefined) || []).map(String);
    const nextVals = ((next[key] as string[] | undefined) || []).map(String);
    const currentVals = ((current[key] as string[] | undefined) || []).map(String);

    const added = nextVals.filter(
      (v) => !viewVals.some((x) => x.toLowerCase() === v.toLowerCase()),
    );
    const removed = viewVals.filter(
      (v) => !nextVals.some((x) => x.toLowerCase() === v.toLowerCase()),
    );
    if (!added.length && !removed.length) {
      // Untouched key: keep the REAL state (the view may have merged
      // bar tokens into this array; writing that back would duplicate
      // them as array filters).
      (result as Record<string, unknown>)[key] = currentVals;
      continue;
    }

    let arrayVals = [...currentVals];
    for (const v of added) {
      if (!parsed.opaque) {
        const canonical = KEY_TO_CANONICAL.get(key)!;
        tokens.push({
          key,
          field: canonical,
          value: v,
          raw: `${canonical}:${quoteIfNeeded(v)}`,
        });
        tokensChanged = true;
      } else if (!arrayVals.some((x) => x.toLowerCase() === v.toLowerCase())) {
        arrayVals.push(v);
      }
    }
    for (const v of removed) {
      const owned = tokens.find(
        (t) => t.key === key && t.value.toLowerCase() === v.toLowerCase(),
      );
      if (owned) {
        tokens = tokens.filter((t) => t !== owned);
        tokensChanged = true;
      }
      arrayVals = arrayVals.filter((x) => x.toLowerCase() !== v.toLowerCase());
    }
    (result as Record<string, unknown>)[key] = arrayVals;
  }

  if (tokensChanged) {
    const q = rebuild(tokens);
    result.q = q || undefined;
  } else {
    result.q = current.q;
  }
  return result;
}
