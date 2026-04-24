import { useMemo, useState } from 'react';
import type { SearchFilters } from '../types';

/**
 * Unified canonical-taxonomy filter section for the Detections page.
 *
 * Three stacked facets — Platform / Data Source / Event Type — each
 * backed by live corpus counts from /api/detections/filters. Replaces
 * ~140 lines of hardcoded Platform subcategories + the never-built
 * Data Source filter + the hardcoded Event Category list.
 *
 * UX choices:
 *  - Count badge on every option ("windows · 3,427") so users can see
 *    what's in the corpus before clicking.
 *  - Top 10 by count shown inline; search box reveals the rest.
 *  - Multi-select within a facet = OR; across facets = AND (handled
 *    backend-side in search.py `_build_conditions`).
 *
 * URL filter keys match backend contract (platforms / event_categories
 * / data_sources_normalized) even though UI labels read "Event Type"
 * and "Data Source" — kept stable to preserve existing bookmarks.
 */

type FacetOption = { value: string; count: number };

interface TelemetryFilterProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  options: {
    platforms: FacetOption[];
    data_sources: FacetOption[];
    event_types: FacetOption[];
  };
}

export function TelemetryFilter({ filters, onFiltersChange, options }: TelemetryFilterProps) {
  return (
    <div className="space-y-4">
      <Facet
        title="Platform"
        filterKey="platforms"
        accent="cyan"
        options={options.platforms}
        selected={filters.platforms || []}
        onChange={(values) =>
          onFiltersChange({ ...filters, platforms: values, offset: 0 })
        }
      />
      <Facet
        title="Data Source"
        filterKey="data_sources_normalized"
        accent="emerald"
        options={options.data_sources}
        selected={filters.data_sources_normalized || []}
        onChange={(values) =>
          onFiltersChange({ ...filters, data_sources_normalized: values, offset: 0 })
        }
      />
      <Facet
        title="Event Type"
        filterKey="event_categories"
        accent="orange"
        options={options.event_types}
        selected={filters.event_categories || []}
        onChange={(values) =>
          onFiltersChange({ ...filters, event_categories: values, offset: 0 })
        }
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Individual facet — handles collapse, typeahead search, and selection.
// ---------------------------------------------------------------------------

type Accent = 'cyan' | 'emerald' | 'orange';

const ACCENT_CLASSES: Record<Accent, { bg: string; text: string; border: string; dot: string }> = {
  cyan: {
    bg: 'bg-cyan-500/15',
    text: 'text-cyan-300',
    border: 'border-cyan-500/30',
    dot: 'bg-cyan-500',
  },
  emerald: {
    bg: 'bg-emerald-500/15',
    text: 'text-emerald-300',
    border: 'border-emerald-500/30',
    dot: 'bg-emerald-500',
  },
  orange: {
    bg: 'bg-orange-500/15',
    text: 'text-orange-300',
    border: 'border-orange-500/30',
    dot: 'bg-orange-500',
  },
};

function Facet({
  title,
  accent,
  options,
  selected,
  onChange,
}: {
  title: string;
  filterKey: keyof SearchFilters;
  accent: Accent;
  options: FacetOption[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [query, setQuery] = useState('');
  const [showAll, setShowAll] = useState(false);

  const accentCls = ACCENT_CLASSES[accent];

  const visible = useMemo(() => {
    // De-prioritize `unknown` — still listed but at the bottom so it
    // doesn't dominate the top-10 view for every facet.
    const sorted = [...options].sort((a, b) => {
      if (a.value === 'unknown') return 1;
      if (b.value === 'unknown') return -1;
      return b.count - a.count;
    });
    const filtered = query
      ? sorted.filter((o) => o.value.toLowerCase().includes(query.toLowerCase()))
      : sorted;
    return showAll || query ? filtered : filtered.slice(0, 10);
  }, [options, query, showAll]);

  const toggle = (value: string) => {
    const next = selected.includes(value)
      ? selected.filter((v) => v !== value)
      : [...selected, value];
    onChange(next);
  };

  const selectedCount = selected.length;
  const hasMore = !query && !showAll && options.length > 10;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className={`w-1.5 h-1.5 rounded-full ${accentCls.dot}`} />
          <span className="text-xs font-display font-semibold text-gray-400 uppercase tracking-wider">
            {title}
          </span>
          {selectedCount > 0 && (
            <span className={`text-xs ${accentCls.text}`}>({selectedCount})</span>
          )}
        </div>
        {selectedCount > 0 && (
          <button
            onClick={() => onChange([])}
            className="text-[10px] text-gray-500 hover:text-matrix-500 uppercase tracking-wide"
          >
            Clear
          </button>
        )}
      </div>

      {options.length > 6 && (
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={`Search ${title.toLowerCase()}...`}
          className="w-full px-3 py-1.5 mb-2 text-xs bg-void-900 border border-void-700 text-gray-300 placeholder-gray-600 focus:outline-none focus:border-matrix-500/50"
        />
      )}

      <div className="space-y-1">
        {visible.map((opt) => (
          <label
            key={opt.value}
            className="flex items-center justify-between gap-2 cursor-pointer group px-2 py-1 rounded hover:bg-void-800/50"
          >
            <span className="flex items-center gap-2 min-w-0 flex-1">
              <input
                type="checkbox"
                checked={selected.includes(opt.value)}
                onChange={() => toggle(opt.value)}
                className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
              />
              <span
                className={`text-sm truncate ${
                  opt.value === 'unknown'
                    ? 'text-gray-500 italic'
                    : 'text-gray-400 group-hover:text-white'
                }`}
                title={opt.value}
              >
                {opt.value}
              </span>
            </span>
            <span className="text-[10px] font-mono text-gray-600 shrink-0">
              {opt.count.toLocaleString()}
            </span>
          </label>
        ))}
        {visible.length === 0 && (
          <div className="text-xs text-gray-600 italic px-2 py-1">No matches</div>
        )}
      </div>

      {hasMore && (
        <button
          onClick={() => setShowAll(true)}
          className="mt-2 text-xs text-gray-500 hover:text-matrix-500 transition-colors"
        >
          + Show all {options.length}
        </button>
      )}
    </div>
  );
}
