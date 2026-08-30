/** Pure typeahead logic for the universal search bar: token parsing
 * under the caret, ranking, and the value-suggestion index built from
 * the /detections/filters facets + MITRE technique catalog. */

import type { QueryFieldSpec } from '../../services/api';

export const PLACEHOLDERS = [
  'actor:"Salt Typhoon"',
  'tech:T1219 platform:windows',
  'eventid:4104 source:splunk',
  'usecase:Ransomware severity:high',
  'process:certutil.exe NOT source:sigma',
  'software:Mimikatz OR title:lsass',
];

export interface Suggestion {
  value: string;      // What gets inserted at the cursor position
  label: string;      // Display text
  hint?: string;      // Right-side hint (description or count)
  kind: 'field' | 'value';
}

export interface TokenInfo {
  before: string;             // text before the current token
  token: string;              // the current token being typed
  after: string;              // text after the current token
  field: string | null;       // field alias if the token has `field:` prefix
  value: string;              // portion after the colon (or whole token if no colon)
}

/** Parse `field:` prefix and remainder from the current token under the cursor. */
export function currentToken(text: string, caret: number): TokenInfo {
  const upto = text.slice(0, caret);
  // A "token" ends at whitespace or a paren, and is bounded on the
  // right by more of the same or end of text. Balanced parens /
  // quoted strings would be nicer; this is deliberately simple.
  const tokenStart = Math.max(
    upto.lastIndexOf(' ') + 1,
    upto.lastIndexOf('(') + 1,
  );
  const rest = text.slice(caret);
  const nextBreak = rest.search(/[\s)]/);
  const tokenEnd = nextBreak === -1 ? text.length : caret + nextBreak;
  const token = text.slice(tokenStart, tokenEnd);
  const colonIdx = token.indexOf(':');
  return {
    before: text.slice(0, tokenStart),
    token,
    after: text.slice(tokenEnd),
    field: colonIdx === -1 ? null : token.slice(0, colonIdx),
    value: colonIdx === -1 ? token : token.slice(colonIdx + 1),
  };
}

/** Rank suggestion candidates by prefix > infix > alpha. */
export function rank<T extends { label: string }>(items: T[], query: string): T[] {
  const q = query.toLowerCase();
  if (!q) return items.slice(0, 20);
  const scored = items.map((it) => {
    const l = it.label.toLowerCase();
    let score = 999;
    if (l.startsWith(q)) score = 0;
    else if (l.includes(q)) score = 1;
    return { it, score };
  }).filter((x) => x.score < 999);
  scored.sort((a, b) => a.score - b.score || a.it.label.localeCompare(b.it.label));
  return scored.slice(0, 20).map((x) => x.it);
}

type FacetLike = { value: string; count?: number; label?: string };

export interface FilterOptionsLike {
  sources?: string[];
  severities?: string[];
  statuses?: string[];
  languages?: string[];
  platforms?: FacetLike[];
  data_sources?: FacetLike[];
  event_types?: FacetLike[];
  use_cases?: FacetLike[];
  mitre_groups?: FacetLike[];
  mitre_software?: FacetLike[];
}

type TechniqueLike = { id: string; name: string; deprecated?: boolean };

/** alias -> value suggestions, from the filter facets + MITRE catalog. */
export function buildValueIndex(
  filterOpts: FilterOptionsLike | undefined,
  techniques: Record<string, TechniqueLike> | undefined,
): Record<string, Suggestion[]> {
  const idx: Record<string, Suggestion[]> = {};
  const add = (aliases: string[], list: FacetLike[]) => {
    const items = list.map((v) => ({
      value: v.value,
      label: v.label || v.value,
      hint: v.count !== undefined ? String(v.count) : undefined,
      kind: 'value' as const,
    }));
    for (const a of aliases) idx[a] = items;
  };
  if (filterOpts) {
    add(['source'], (filterOpts.sources || []).map((v) => ({ value: v })));
    add(['sev', 'severity'], (filterOpts.severities || []).map((v) => ({ value: v })));
    add(['status'], (filterOpts.statuses || []).map((v) => ({ value: v })));
    add(['lang', 'language'], (filterOpts.languages || []).map((v) => ({ value: v })));
    add(['platform'], filterOpts.platforms || []);
    add(['data', 'datasource'], filterOpts.data_sources || []);
    add(['event', 'eventtype'], filterOpts.event_types || []);
    add(['usecase', 'story', 'use_case'], filterOpts.use_cases || []);
    // For actor / software: the facet gives us IDs (G0016 etc). Users
    // can also type names -- the backend resolves either way.
    add(['actor', 'group'], filterOpts.mitre_groups || []);
    add(['software', 'tool', 'malware'], filterOpts.mitre_software || []);
  }
  if (techniques && Object.keys(techniques).length) {
    const techItems = Object.values(techniques)
      .filter((t) => !t.deprecated)
      .map((t) => ({ value: t.id, label: `${t.id} · ${t.name}`, kind: 'value' as const }));
    for (const a of ['tech', 'technique']) idx[a] = techItems;
  }
  return idx;
}

/** Suggestions for the token under the caret: field names before a
 * colon, known values after one. */
export function suggestFor(
  draft: string,
  caret: number,
  fields: QueryFieldSpec[],
  valueIndex: Record<string, Suggestion[]>,
): { suggestions: Suggestion[]; tokenInfo: TokenInfo } {
  const info = currentToken(draft, caret);
  if (info.field === null) {
    // No colon yet -- suggesting field names. Offer each field's
    // canonical (first) alias only; secondary aliases (`malware:`,
    // `sev:`, ...) still parse and still surface once the user starts
    // typing one, but don't clutter the default list.
    const typed = info.value.toLowerCase();
    const fieldSug: Suggestion[] = fields.flatMap((f) =>
      f.aliases
        .filter((a, i) => i === 0 || (typed.length > 0 && a.startsWith(typed)))
        .map((a) => ({
          value: `${a}:`,
          label: `${a}:`,
          hint: f.description,
          kind: 'field' as const,
        })),
    );
    return { suggestions: rank(fieldSug, info.value), tokenInfo: info };
  }
  // Have `field:` -- suggest values for it (if we know any). A
  // suggestion identical to what's already typed is noise (and used
  // to trap Enter in apply-loops), so drop it.
  const values = valueIndex[info.field.toLowerCase()] || [];
  const typedValue = info.value.replace(/^"|"$/g, '').toLowerCase();
  const remaining = values.filter((v) => v.value.toLowerCase() !== typedValue);
  return { suggestions: rank(remaining, info.value), tokenInfo: info };
}

/** Text after applying a suggestion at the current token, plus where
 * the caret should land. */
export function applyTo(draft: TokenInfo, sug: Suggestion): { next: string; caret: number } {
  let insertion = sug.value;
  // If we're completing a value and it contains a space, quote it.
  if (sug.kind === 'value' && /\s/.test(insertion) && !insertion.startsWith('"')) {
    insertion = `"${insertion}"`;
  }
  // Replace the current token's value slot (or the whole token for
  // field completions).
  const middle = sug.kind === 'field' ? insertion : `${draft.field ? `${draft.field}:` : ''}${insertion}`;
  return { next: `${draft.before}${middle}${draft.after}`, caret: (draft.before + middle).length };
}

/** Best-effort auto-fix for an unknown-field parse error: replace the
 * first `name:` token whose name is not a known alias. Scans every
 * token -- with a valid field first (`source:sigma sevrity:high`) a
 * non-global replace only ever looked at `source:`. */
export function fixUnknownField(draft: string, fields: QueryFieldSpec[], suggestion: string): string {
  let fixed = false;
  return draft.replace(/\b(\w+):/gi, (m, name: string) => {
    if (fixed || fields.some((f) => f.aliases.includes(name.toLowerCase()))) return m;
    fixed = true;
    return `${suggestion}:`;
  });
}
