import type { SearchFilters } from '../types';

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
  severities: 'Severity',
  languages: 'Language',
  platforms: 'Platform',
  data_sources_normalized: 'Data Source',
  event_categories: 'Event Type',
  mitre_tactics: 'Tactic',
  mitre_techniques: 'Technique',
  tags: 'Tag',
  event_ids: 'Event ID',
  process_names: 'Process',
  query_complexity: 'Complexity',
  api_actions: 'API Action',
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
};
const DEFAULT_ACCENT = 'bg-void-800 text-gray-300 border-void-600';

export function ActiveFilterPills({ filters, onFiltersChange }: ActiveFilterPillsProps) {
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

  if (pills.length === 0 && !filters.search) {
    return null;
  }

  const removePill = (key: keyof SearchFilters, value: string) => {
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
        return (
          <button
            key={`${key}:${value}`}
            onClick={() => removePill(key, value)}
            aria-label={`Remove filter ${label}: ${value}`}
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono border ${accent} hover:opacity-80 transition-opacity`}
          >
            <span className="text-[10px] opacity-60">{label}:</span>
            <span>{value}</span>
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
