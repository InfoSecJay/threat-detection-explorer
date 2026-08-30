import type { SearchFilters } from '../types';
import { resolveGroup, resolveSoftware } from '../services/mitreLookup';
import { useEventIds } from '../hooks/useEventIds';

/**
 * Horizontal pill row showing every currently-applied filter, each
 * with an X to remove. Rendered above the results table so the user
 * can see exactly what's narrowing the view without reading the
 * sidebar. Click any pill to drop that value from its filter.
 *
 * Kept deliberately framework-free — no dropdowns or modals, just
 * inline pills. Accessibility: each pill is a button with an aria-label.
 */

interface ActiveFilterPillsProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
}

// Pretty labels for each filter key. Falls back to the raw key.
const LABELS: Record<string, string> = {
  sources: 'Source',
  statuses: 'Status',
  building_block: 'Building blocks',
  min_quality: 'Completeness',
  severities: 'Severity',
  languages: 'Language',
  platforms: 'Platform',
  data_sources_normalized: 'Data Source',
  event_categories: 'Event Type',
  mitre_tactics: 'Tactic',
  mitre_techniques: 'Technique',
  mitre_groups: 'Actor',
  mitre_software: 'Software',
  tags: 'Tag',
  event_ids: 'Event ID',
  process_names: 'Process',
  query_complexity: 'Complexity',
  api_actions: 'API Action',
  use_cases: 'Use Case',
  file_paths: 'File Path',
  registry_keys: 'Registry',
  network_indicators: 'Network',
  target_resources: 'Target',
  source_tables: 'Table',
};

// Accent color per filter type so pills are scan-able at a glance.
const ACCENTS: Record<string, string> = {
  sources: 'bg-matrix-500/15 text-matrix-500 border-matrix-500/30',
  platforms: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  data_sources_normalized: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  event_categories: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  severities: 'bg-red-500/15 text-red-300 border-red-500/30',
  mitre_tactics: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  mitre_techniques: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  mitre_groups: 'bg-breach-500/15 text-breach-400 border-breach-500/30',
  mitre_software: 'bg-breach-500/15 text-breach-400 border-breach-500/30',
  use_cases: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
};
const DEFAULT_ACCENT = 'bg-void-800 text-gray-300 border-void-600';

export function ActiveFilterPills({ filters, onFiltersChange }: ActiveFilterPillsProps) {
  // Hook before any early return (rules of hooks).
  const { labels: eventIdLabels } = useEventIds();
  const pills: Array<{ key: keyof SearchFilters; value: string }> = [];

  (Object.keys(LABELS) as Array<keyof SearchFilters>).forEach((key) => {
    const values = filters[key];
    if (Array.isArray(values)) {
      values.forEach((v) => {
        if (typeof v === 'string' && v) {
          pills.push({ key, value: v });
        }
      });
    }
  });

  // Scalar tri-state: one pill, value is the human reading.
  if (filters.building_block !== undefined) {
    pills.push({ key: 'building_block', value: filters.building_block ? 'only' : 'hidden' });
  }
  if (filters.min_quality !== undefined) {
    pills.push({ key: 'min_quality', value: `>= ${filters.min_quality}` });
  }

  if (pills.length === 0 && !filters.search) {
    return null;
  }

  const removePill = (key: keyof SearchFilters, value: string) => {
    if (key === 'building_block') {
      onFiltersChange({ ...filters, building_block: undefined, offset: 0 });
      return;
    }
    if (key === 'min_quality') {
      onFiltersChange({ ...filters, min_quality: undefined, offset: 0 });
      return;
    }
    const current = (filters[key] as string[]) || [];
    onFiltersChange({
      ...filters,
      [key]: current.filter((v) => v !== value),
      offset: 0,
    });
  };

  const clearAll = () => {
    onFiltersChange({
      search: filters.search,
      offset: 0,
      limit: filters.limit,
      sort_by: filters.sort_by,
      sort_order: filters.sort_order,
    });
  };

  return (
    <div className="flex flex-wrap items-center gap-2 mb-4 pb-3 border-b border-void-800">
      <span className="text-[10px] font-mono text-gray-600 uppercase tracking-wider">
        Filters:
      </span>
      {pills.map(({ key, value }) => {
        const accent = ACCENTS[key] || DEFAULT_ACCENT;
        const label = LABELS[key] || key;
        // Resolve display name for MITRE Group/Software IDs so the pill
        // shows "APT29" not "G0016". Filter URL still carries the raw
        // ID — the removal handler references `value` unchanged.
        let display: string = value;
        if (key === 'mitre_groups') display = resolveGroup(value).name;
        else if (key === 'mitre_software') display = resolveSoftware(value).name;
        else if (key === 'event_ids' && eventIdLabels[value]) display = `${value} ${eventIdLabels[value]}`;
        return (
          <button
            key={`${key}:${value}`}
            onClick={() => removePill(key, value)}
            aria-label={`Remove filter ${label}: ${display}`}
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono border ${accent} hover:opacity-80 transition-opacity`}
          >
            <span className="text-[10px] opacity-60">{label}:</span>
            <span>{display}</span>
            <span className="ml-0.5 opacity-60 hover:opacity-100">✕</span>
          </button>
        );
      })}
      {pills.length > 0 && (
        <button
          onClick={clearAll}
          className="ml-auto text-[10px] font-mono text-gray-500 hover:text-matrix-500 uppercase tracking-wide"
        >
          Clear all
        </button>
      )}
    </div>
  );
}
