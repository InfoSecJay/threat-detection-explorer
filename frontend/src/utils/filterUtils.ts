/**
 * SearchFilters helpers shared across the FilterSheet, ActiveFilterPills,
 * and any callers that need to reason about "how many array filters are
 * active". `q` and `search` are intentionally not counted — they render
 * in the search bar itself, not as chips.
 */

import type { SearchFilters } from '../types';

// Keys we count in the active-filter badge. Mirrors the FilterPanel
// sections. Deliberately excludes filters that still exist on the
// SearchFilters type + backend API but that the panel no longer
// exposes (statuses, mitre_groups, mitre_software, use_cases,
// query_complexity, event_ids, target_resources, source_tables) --
// if they arrive from a bookmarked URL the backend still honors
// them, they just don't count as user-visible facets since there's
// no UI to toggle them.
const ARRAY_FILTER_KEYS: Array<keyof SearchFilters> = [
  'sources',
  'severities',
  'languages',
  'mitre_tactics',
  'mitre_techniques',
  'tags',
  'platforms',
  'event_categories',
  'data_sources_normalized',
  'process_names',
  'api_actions',
  'file_paths',
  'registry_keys',
  'network_indicators',
];

export function countActiveFilters(filters: SearchFilters): number {
  let n = 0;
  for (const key of ARRAY_FILTER_KEYS) {
    const v = filters[key];
    if (Array.isArray(v) && v.length > 0) n += v.length;
  }
  return n;
}
