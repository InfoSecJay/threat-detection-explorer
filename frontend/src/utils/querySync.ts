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
  // Extracted-observable surfaces (observables v2)
  { key: 'process_names', canonical: 'process', aliases: ['process', 'proc', 'exe'] },
  { key: 'file_paths', canonical: 'path', aliases: ['path', 'file', 'filepath'] },
  { key: 'registry_keys', canonical: 'registry', aliases: ['registry', 'reg', 'regkey'] },
  { key: 'network_indicators', canonical: 'network', aliases: ['network', 'ioc', 'indicator', 'ip', 'domain'] },
  { key: 'api_actions', canonical: 'action', aliases: ['action', 'api', 'apiaction'] },
  { key: 'event_ids', canonical: 'eventid', aliases: ['eventid', 'event_id', 'eid'] },
  { key: 'source_tables', canonical: 'table', aliases: ['table', 'index', 'logtype', 'datamodel'] },
  { key: 'target_resources', canonical: 'resource', aliases: ['resource', 'target'] },
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

// A same-field OR group as written by `rebuild`:
// `(source:sigma OR source:elastic OR source:"x y")`. The ONLY grouping
// syntax the sheet round-trips; anything else in parens stays opaque.
const OR_GROUP_RE = /\(\s*(\w+:(?:"[^"]*"|[^\s()"]+)(?:\s+OR\s+\w+:(?:"[^"]*"|[^\s()"]+))+)\s*\)/gi;

export function parseBar(q: string): ParsedBar {
  const trimmed = (q || '').trim();
  if (!trimmed) return { tokens: [], opaque: false };

  // Lift same-field OR groups out first. Two sheet ticks in one
  // dimension MUST be OR (`source:sigma source:elastic` is AND at the
  // API and matches nothing), so `rebuild` writes them grouped and
  // this is the reverse. Groups mixing fields fall through to the
  // opaque check below.
  const groupTokens: BarToken[] = [];
  const remainder = trimmed.replace(OR_GROUP_RE, (whole, inner: string) => {
    const parts = inner.split(/\s+OR\s+/i);
    const parsed = parts.map((p) => {
      const colon = p.indexOf(':');
      return { field: p.slice(0, colon).toLowerCase(), value: unquote(p.slice(colon + 1)), raw: p };
    });
    if (new Set(parsed.map((p) => p.field)).size !== 1) return whole;
    for (const p of parsed) {
      groupTokens.push({ key: ALIAS_TO_KEY.get(p.field) ?? null, field: p.field, value: p.value, raw: p.raw });
    }
    return ' ';
  }).trim();

  // Anything beyond a flat AND of terms is opaque. `-term`, `field:>x`
  // ranges, and grouping all change semantics under partial edits.
  if (/[()[\]{]/.test(remainder) || /(^|\s)(OR|NOT)(\s|$)/i.test(remainder) || /(^|\s)-\w/.test(remainder)) {
    return { tokens: [], opaque: true };
  }

  const tokens: BarToken[] = [...groupTokens];
  for (const raw of splitTokens(remainder)) {
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

/** Rebuild q from remaining tokens: implicit AND between dimensions,
 * an explicit parenthesized OR within one (see OR_GROUP_RE). */
function rebuild(tokens: BarToken[]): string {
  const byField = new Map<string, BarToken[]>();
  for (const t of tokens) {
    if (!t.key || !t.field) continue;
    const list = byField.get(t.field) ?? [];
    list.push(t);
    byField.set(t.field, list);
  }
  const emitted = new Set<string>();
  const parts: string[] = [];
  for (const t of tokens) {
    if (!t.key || !t.field) {
      parts.push(t.raw);
      continue;
    }
    if (emitted.has(t.field)) continue;
    emitted.add(t.field);
    const group = byField.get(t.field)!;
    parts.push(group.length === 1 ? group[0].raw : `(${group.map((g) => g.raw).join(' OR ')})`);
  }
  return parts.join(' ');
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
