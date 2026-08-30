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

// Scalar (single-value) filters that also have a bar field. Mirrors the
// backend `kind="bool"` specs. `parse` turns the typed token value into
// the filter value (undefined = not a recognised value, token ignored);
// `format` is the inverse for writing a token from the sheet (#47).
type ScalarKey = 'building_block' | 'min_quality';
type ScalarValue = boolean | number;
const SCALAR_MAP: {
  key: ScalarKey;
  canonical: string;
  aliases: string[];
  parse: (raw: string) => ScalarValue | undefined;
  format: (value: ScalarValue) => string;
}[] = [
  {
    key: 'building_block',
    canonical: 'building_block',
    aliases: ['building_block', 'bb', 'signal_only'],
    parse: (raw) => (raw.toLowerCase() === 'true' ? true : raw.toLowerCase() === 'false' ? false : undefined),
    format: (value) => String(value),
  },
  {
    // Only the ">= N" shape round-trips (that is what the sheet
    // control writes); other comparisons / ranges stay bar-only.
    key: 'min_quality',
    canonical: 'quality',
    aliases: ['quality', 'hygiene', 'score', 'completeness'],
    parse: (raw) => {
      const m = /^>=(\d{1,3})$/.exec(raw.trim());
      if (!m) return undefined;
      const n = Number(m[1]);
      return n <= 100 ? n : undefined;
    },
    format: (value) => `>=${value}`,
  },
];
const SCALAR_KEYS = new Set<string>(SCALAR_MAP.map((s) => s.key));

const ALIAS_TO_KEY = new Map<string, keyof SearchFilters>([
  ...FIELD_MAP.flatMap((f) => f.aliases.map((a) => [a, f.key] as [string, keyof SearchFilters])),
  ...SCALAR_MAP.flatMap((s) => s.aliases.map((a) => [a, s.key] as [string, keyof SearchFilters])),
]);
const KEY_TO_CANONICAL = new Map<keyof SearchFilters, string>([
  ...FIELD_MAP.map((f) => [f.key, f.canonical] as [keyof SearchFilters, string]),
  ...SCALAR_MAP.map((s) => [s.key, s.canonical] as [keyof SearchFilters, string]),
]);

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
    if (SCALAR_KEYS.has(token.key)) {
      // `building_block:true` in the bar lights the sidebar tri-state.
      // An explicit sidebar value wins over the bar (they compose via
      // AND at the API either way).
      const spec = SCALAR_MAP.find((s) => s.key === token.key)!;
      const parsedValue = spec.parse(token.value);
      if (parsedValue !== undefined && view[spec.key] === undefined) {
        (view as Record<string, unknown>)[spec.key] = parsedValue;
      }
      continue;
    }
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

  // Scalar dimensions: the sheet's tri-state vs the bar token (#47).
  for (const spec of SCALAR_MAP) {
    const viewVal = view[spec.key];
    const nextVal = next[spec.key];
    if (viewVal === nextVal) {
      // Untouched: keep the REAL state (undefined when the bar owns it).
      (result as Record<string, unknown>)[spec.key] = current[spec.key];
      continue;
    }
    const owned = tokens.filter((t) => t.key === spec.key);
    if (owned.length) {
      tokens = tokens.filter((t) => t.key !== spec.key);
      tokensChanged = true;
    }
    if (nextVal === undefined) {
      (result as Record<string, unknown>)[spec.key] = undefined;
    } else if (!parsed.opaque) {
      tokens.push({
        key: spec.key,
        field: spec.canonical,
        value: spec.format(nextVal),
        raw: `${spec.canonical}:${spec.format(nextVal)}`,
      });
      tokensChanged = true;
      (result as Record<string, unknown>)[spec.key] = undefined;
    } else {
      (result as Record<string, unknown>)[spec.key] = nextVal;
    }
  }

  if (tokensChanged) {
    const q = rebuild(tokens);
    result.q = q || undefined;
  } else {
    result.q = current.q;
  }
  return result;
}
