/** Catalog sort defaults (Jay, 2026-09-17): newest rules first.
 *
 * A bar with free text defaults to Relevance instead, so `citrix` keeps
 * ranking title matches first (the v3 teardown asked to keep that);
 * field-only queries (`tech:T1055 source:sigma`) and the empty catalog
 * sort newest-first. Mirrors the backend's free_text_terms(): fielded
 * and negated terms do not rank, so they do not flip the default. */

import type { SearchFilters } from '../types';

export const NEWEST_FIRST = 'rule_created_date';
export const RELEVANCE = 'relevance';

// One query term: an optional `field:` prefix, then a quoted phrase or
// a bare word.
const TERM = '(?:\\w+:)?(?:"[^"]*"|\\S+)';
// `NOT term`, `-term` and `!term` are excluded from ranking upstream.
const NOT_RE = new RegExp(`\\bNOT\\s+${TERM}`, 'g');
const NEGATED_RE = new RegExp(`(?:^|\\s)[-!]${TERM}`, 'g');
const FIELDED_RE = /\+?\w+:(?:"[^"]*"|\S+)/g;
const OPERATOR_RE = /\b(?:AND|OR|NOT)\b|[()[\]{}]/g;

/** True when q carries at least one bare (unfielded, non-negated) term. */
export function hasFreeText(q: string | undefined): boolean {
  const rest = (q || '')
    .replace(NOT_RE, ' ')
    .replace(NEGATED_RE, ' ')
    .replace(FIELDED_RE, ' ')
    .replace(OPERATOR_RE, ' ')
    .trim();
  return rest.length > 0;
}

/** The sort the catalog uses when the URL names none. */
export function defaultSortFor(filters: Pick<SearchFilters, 'q' | 'search'>): string {
  return filters.search || hasFreeText(filters.q) ? RELEVANCE : NEWEST_FIRST;
}
