/**
 * SearchFilters helpers shared across the FilterSheet, ActiveFilterPills,
 * and any callers that need to reason about "how many array filters are
 * active". `q` and `search` are intentionally not counted — they render
 * in the search bar itself, not as chips.
 */

import type { SearchFilters } from '../types';

const ARRAY_FILTER_KEYS: Array<keyof SearchFilters> = [
  'sources',
  'statuses',
  'severities',
  'languages',
  'mitre_tactics',
  'mitre_techniques',
  'mitre_groups',
  'mitre_software',
  'tags',
  'platforms',
  'event_categories',
  'data_sources_normalized',
  'use_cases',
  'event_ids',
  'process_names',
  'query_complexity',
  'api_actions',
  'file_paths',
  'registry_keys',
  'network_indicators',
  'target_resources',
  'source_tables',
];

export function countActiveFilters(filters: SearchFilters): number {
  let n = 0;
  for (const key of ARRAY_FILTER_KEYS) {
    const v = filters[key];
    if (Array.isArray(v) && v.length > 0) n += v.length;
  }
  return n;
}
