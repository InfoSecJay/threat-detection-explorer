import { useMemo, useState } from 'react';
import type { SearchFilters } from '../types';
import { DOMAIN_LABELS, PLATFORM_LABELS } from '../constants/taxonomy';

/**
 * Unified canonical-taxonomy filter section for the Detections page.
 *
 * Five stacked facets — Domain / Platform / Data Source / Event Type /
 * Product (#103) — each
 * backed by live corpus counts from /api/detections/facets. Replaces
 * ~140 lines of hardcoded Platform subcategories + the never-built
 * Data Source filter + the hardcoded Event Category list.
 *
 * UX choices:
 *  - Count badge on every option ("windows · 3,427") so users can see
 *    what's in the corpus before clicking.
 *  - Top 10 by count shown inline; search box reveals the rest.
 *  - Multi-select within a facet = OR; across facets = AND (handled
 *    backend-side in search.py `_build_conditions`).
 *  - Event Type is a two-level hierarchy (#104): parents with a union
 *    count and an expander; selecting a parent filters on the parent
 *    plus all its children (expanded server-side), so the children
 *    render as included rather than selectable.
 *
 * URL filter keys match backend contract (platforms / event_categories
 * / data_sources_normalized) even though UI labels read "Event Type"
 * and "Data Source" — kept stable to preserve existing bookmarks.
 */

type FacetOption = { value: string; count: number };
export type FacetGroupOption = { value: string; count: number; children: FacetOption[] };

interface TelemetryFilterProps {
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  options: {
    /** Attack-surface domains (#103): endpoint, identity, cloud, saas, network, email, devops, data. */
    domains?: FacetOption[];
    platforms: FacetOption[];
    data_sources: FacetOption[];
    event_types: FacetOption[];
    /** Vendor / application whose telemetry the rule reads (#103). */
    products?: FacetOption[];
    /** Nested event types; when present the Event Type facet renders grouped. */
    event_type_groups?: FacetGroupOption[];
  };
}

export function TelemetryFilter({ filters, onFiltersChange, options }: TelemetryFilterProps) {
  const groups = options.event_type_groups;
  return (
    <div className="space-y-4">
      <Facet
        title="Domain"
        filterKey="domains"
        accent="purple"
        options={options.domains || []}
        selected={filters.domains || []}
        labels={DOMAIN_LABELS}
        onChange={(values) =>
          onFiltersChange({ ...filters, domains: values, offset: 0 })
        }
      />
      <Facet
        title="Platform"
        filterKey="platforms"
        accent="cyan"
        options={options.platforms}
        selected={filters.platforms || []}
        labels={PLATFORM_LABELS}
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
      {groups && groups.length > 0 ? (
        <GroupedFacet
          title="Event Type"
          accent="orange"
          groups={groups}
          selected={filters.event_categories || []}
          onChange={(values) =>
            onFiltersChange({ ...filters, event_categories: values, offset: 0 })
          }
        />
      ) : (
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
      )}
      <Facet
        title="Product"
        filterKey="products"
        accent="amber"
        options={options.products || []}
        selected={filters.products || []}
        onChange={(values) =>
          onFiltersChange({ ...filters, products: values, offset: 0 })
        }
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Individual facet — handles collapse, typeahead search, and selection.
// ---------------------------------------------------------------------------

export type Accent = 'cyan' | 'emerald' | 'orange' | 'red' | 'amber' | 'purple';

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
  red: {
    bg: 'bg-red-500/15',
    text: 'text-red-300',
    border: 'border-red-500/30',
    dot: 'bg-red-500',
  },
  amber: {
    bg: 'bg-amber-500/15',
    text: 'text-amber-300',
    border: 'border-amber-500/30',
    dot: 'bg-amber-500',
  },
  purple: {
    bg: 'bg-purple-500/15',
    text: 'text-purple-300',
    border: 'border-purple-500/30',
    dot: 'bg-purple-500',
  },
};

function FacetHeader({
  title,
  accent,
  selectedCount,
  onClear,
}: {
  title: string;
  accent: Accent;
  selectedCount: number;
  onClear: () => void;
}) {
  const accentCls = ACCENT_CLASSES[accent];
  return (
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
          onClick={onClear}
          className="text-[10px] text-gray-500 hover:text-matrix-500 uppercase tracking-wide"
        >
          Clear
        </button>
      )}
    </div>
  );
}

export function Facet({
  title,
  accent,
  options,
  selected,
  onChange,
  labels,
}: {
  title: string;
  filterKey: keyof SearchFilters;
  accent: Accent;
  options: FacetOption[];
  selected: string[];
  onChange: (values: string[]) => void;
  /** Optional {value: human label} map (e.g. event-ID dictionary):
   * the raw value stays the filter key, the label renders beside it
   * and is searchable. */
  labels?: Record<string, string>;
}) {
  const [query, setQuery] = useState('');
  const [showAll, setShowAll] = useState(false);

  const visible = useMemo(() => {
    // De-prioritize `unknown` — still listed but at the bottom so it
    // doesn't dominate the top-10 view for every facet.
    const sorted = [...options].sort((a, b) => {
      if (a.value === 'unknown') return 1;
      if (b.value === 'unknown') return -1;
      return b.count - a.count;
    });
    const q = query.toLowerCase();
    const filtered = query
      ? sorted.filter(
          (o) =>
            o.value.toLowerCase().includes(q) ||
            (labels?.[o.value] || '').toLowerCase().includes(q),
        )
      : sorted;
    return showAll || query ? filtered : filtered.slice(0, 10);
  }, [options, query, showAll, labels]);

  const toggle = (value: string) => {
    const next = selected.includes(value)
      ? selected.filter((v) => v !== value)
      : [...selected, value];
    onChange(next);
  };

  const hasMore = !query && !showAll && options.length > 10;

  return (
    <div>
      <FacetHeader title={title} accent={accent} selectedCount={selected.length} onClear={() => onChange([])} />

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
                title={labels?.[opt.value] ? `${opt.value} - ${labels[opt.value]}` : opt.value}
              >
                {opt.value}
                {labels?.[opt.value] && (
                  <span className="ml-1.5 text-[11px] text-gray-500 group-hover:text-gray-300">
                    {labels[opt.value]}
                  </span>
                )}
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

// ---------------------------------------------------------------------------
// Grouped facet (#104) — parents with a union count and an expander;
// children are selectable on their own, or shown as included when
// their parent is selected (the backend expands a parent to its
// children, so ticking both would be redundant).
// ---------------------------------------------------------------------------

export function GroupedFacet({
  title,
  accent,
  groups,
  selected,
  onChange,
}: {
  title: string;
  accent: Accent;
  groups: FacetGroupOption[];
  selected: string[];
  onChange: (values: string[]) => void;
}) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const visible = useMemo(() => {
    const sorted = [...groups].sort((a, b) => {
      if (a.value === 'unknown') return 1;
      if (b.value === 'unknown') return -1;
      return b.count - a.count;
    });
    const q = query.toLowerCase();
    if (!q) return sorted;
    return sorted
      .map((g) => {
        const parentHit = g.value.toLowerCase().includes(q);
        const kids = g.children.filter((c) => c.value.toLowerCase().includes(q));
        if (!parentHit && kids.length === 0) return null;
        return { ...g, children: parentHit ? g.children : kids };
      })
      .filter((g): g is FacetGroupOption => g !== null);
  }, [groups, query]);

  const toggle = (value: string) => {
    const next = selected.includes(value)
      ? selected.filter((v) => v !== value)
      : [...selected, value];
    onChange(next);
  };

  const isOpen = (g: FacetGroupOption) => (query ? true : !!open[g.value]);

  return (
    <div data-testid="grouped-facet">
      <FacetHeader title={title} accent={accent} selectedCount={selected.length} onClear={() => onChange([])} />

      {groups.length > 6 && (
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={`Search ${title.toLowerCase()}...`}
          className="w-full px-3 py-1.5 mb-2 text-xs bg-void-900 border border-void-700 text-gray-300 placeholder-gray-600 focus:outline-none focus:border-matrix-500/50"
        />
      )}

      <div className="space-y-1">
        {visible.map((g) => {
          const parentSelected = selected.includes(g.value);
          const hasKids = g.children.length > 0;
          const expanded = hasKids && isOpen(g);
          return (
            <div key={g.value}>
              <div className="flex items-center justify-between gap-1 group px-2 py-1 rounded hover:bg-void-800/50">
                <label className="flex items-center gap-2 min-w-0 flex-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={parentSelected}
                    onChange={() => toggle(g.value)}
                    className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
                  />
                  <span
                    className={`text-sm truncate ${
                      g.value === 'unknown' ? 'text-gray-500 italic' : hasKids ? 'text-gray-300 group-hover:text-white' : 'text-gray-400 group-hover:text-white'
                    }`}
                    title={hasKids ? `${g.value} - includes ${g.children.length} specific kinds` : g.value}
                  >
                    {g.value}
                  </span>
                </label>
                <span className="text-[10px] font-mono text-gray-600 shrink-0">{g.count.toLocaleString()}</span>
                {hasKids && (
                  <button
                    type="button"
                    onClick={() => setOpen((o) => ({ ...o, [g.value]: !o[g.value] }))}
                    aria-label={`${expanded ? 'Collapse' : 'Expand'} ${g.value}`}
                    aria-expanded={expanded}
                    className="text-[10px] font-mono text-gray-500 hover:text-matrix-400 w-4 text-center shrink-0"
                  >
                    {expanded ? '−' : '+'}
                  </button>
                )}
              </div>
              {expanded && (
                <div className="ml-5 border-l border-void-700 pl-2 space-y-0.5">
                  {g.children.map((c) => {
                    const included = parentSelected;
                    const checked = included || selected.includes(c.value);
                    return (
                      <label
                        key={c.value}
                        className={`flex items-center justify-between gap-2 px-2 py-0.5 rounded ${included ? 'opacity-70' : 'cursor-pointer hover:bg-void-800/50'}`}
                        title={included ? `${c.value} - included by ${g.value}` : c.value}
                      >
                        <span className="flex items-center gap-2 min-w-0 flex-1">
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={included}
                            onChange={() => toggle(c.value)}
                            className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
                          />
                          <span className="text-xs truncate text-gray-400">{c.value}</span>
                        </span>
                        <span className="text-[10px] font-mono text-gray-600 shrink-0">{c.count.toLocaleString()}</span>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
        {visible.length === 0 && (
          <div className="text-xs text-gray-600 italic px-2 py-1">No matches</div>
        )}
      </div>
    </div>
  );
}
