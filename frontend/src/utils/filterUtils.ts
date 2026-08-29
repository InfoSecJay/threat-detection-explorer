/**
 * SearchFilters helpers shared across the FilterSheet, ActiveFilterPills,
 * and any callers that need to reason about "how many array filters are
 * active". `q` and `search` are intentionally not counted — they render
 * in the search bar itself, not as chips.
 */

import type { SearchFilters } from '../types';

// Keys we count in the active-filter badge -- every array filter that
// ActiveFilterPills renders as a chip. This is deliberately BROADER than
// the FilterPanel's sections: with the bar<->sheet translation (#13),
// values arriving from the search bar (`actor:G0016`, `usecase:...`)
// or from a bookmarked URL (process_names=...) appear as removable
// pills even though the sheet has no section for them, so the badge
// must count what the user can SEE and remove, not what the sheet
// happens to expose. Keep in sync with ActiveFilterPills LABELS.
export const ARRAY_FILTER_KEYS: Array<keyof SearchFilters> = [
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
  // Scalar tri-state (building blocks only / hidden) counts as one.
  if (filters.building_block !== undefined) n += 1;
  return n;
}
