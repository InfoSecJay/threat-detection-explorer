/** Static vocabularies and helpers shared by the filter sidebar sections. */

import type { SearchFilters } from '../../types';
import type { FacetOption } from '../../services/api';

/** What every section needs to read and write the active query. */
export interface FilterCtx {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  /** Add/remove one value in a multi-select dimension (resets paging). */
  toggle: (field: keyof SearchFilters, value: string, checked: boolean) => void;
}

// Rule maturity vocabulary (Sigma's, preserved 1:1 -- issue #26).
// Options with no corpus count are hidden unless already selected, so
// `deprecated` (never ingested) does not clutter the list.
export const STATUS_OPTIONS: Array<{ value: string; label: string; color: string; hint: string }> = [
  { value: 'stable', label: 'Stable', color: '#00ff41', hint: 'Field-proven; vendor considers it production-ready' },
  { value: 'test', label: 'Test', color: '#38bdf8', hint: 'Works, not yet field-proven (Sigma "test")' },
  { value: 'experimental', label: 'Experimental', color: '#fbbf24', hint: 'Early-stage or disabled by default upstream' },
  { value: 'deprecated', label: 'Deprecated', color: '#ff0040', hint: 'Retired upstream' },
  { value: 'unsupported', label: 'Unsupported', color: '#ff9500', hint: 'Cannot run on current tooling (Sigma "unsupported")' },
  { value: 'unknown', label: 'Unknown', color: '#6b7280', hint: 'Source carries no maturity concept' },
];

export const SEVERITY_OPTIONS: Array<{ value: string; label: string; color: string }> = [
  { value: 'critical', label: 'Critical', color: '#ff0040' },
  { value: 'high', label: 'High', color: '#ff9500' },
  { value: 'medium', label: 'Medium', color: '#fbbf24' },
  { value: 'low', label: 'Low', color: '#00ff41' },
  // "Not specified" not "Unknown": these are rules whose upstream
  // publishes no severity, surfaced honestly instead of defaulted to
  // medium (teardown R08 / #106).
  { value: 'unknown', label: 'Not specified', color: '#6b7280' },
];

/** Display labels for query languages. Unlisted values render raw --
 * the facet decides what exists, this only prettifies. */
export const LANGUAGE_LABELS: Record<string, string> = {
  sigma: 'Sigma',
  spl: 'SPL (Splunk)',
  eql: 'EQL (Elastic)',
  esql: 'ES|QL (Elastic)',
  // Both Sentinel analytic rules and Kibana KQL rules carry `kql`;
  // the old "KQL (Kibana)" label misdescribed 3,000+ Sentinel rules.
  kql: 'KQL (Sentinel / Kibana)',
  mql: 'MQL (Sublime)',
  yaral: 'YARA-L (Chronicle)',
  oie: 'OIE (Okta)',
  python: 'Python (Panther)',
  panther_correlation: 'Panther Correlation',
  panther: 'Panther Declarative',
  osquery: 'osquery',
  ml: 'ML',
  threat_match: 'Threat Match',
};

/** [{value, count}] -> {value: count} lookup. */
export function countMap(facet?: FacetOption[]): Record<string, number> {
  const map: Record<string, number> = {};
  for (const f of facet || []) map[f.value] = f.count;
  return map;
}
