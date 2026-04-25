/**
 * Filter bar for the Catalog Activity strip — narrows the trending +
 * recent-rules queries by source and platform. The platforms-trending
 * query intentionally drops its own `platforms` filter (it would be
 * circular — that's the grouping key).
 */

import { useFilterOptions } from '../../hooks/useDetections';
import { sourceTheme as sourceConfig } from '../../constants/style';
import type { ActivityFilters } from '../../services/api';

export function ActivityFilterBar({
  filters,
  setFilters,
}: {
  filters: ActivityFilters;
  setFilters: (f: ActivityFilters) => void;
}) {
  const { data: options } = useFilterOptions();
  const sources = options?.sources || [];
  const platforms = options?.platforms || [];

  const toggleSource = (src: string) => {
    const curr = filters.sources || [];
    const next = curr.includes(src) ? curr.filter((s) => s !== src) : [...curr, src];
    setFilters({ ...filters, sources: next.length ? next : undefined });
  };

  const setPlatform = (plat: string | null) => {
    setFilters({ ...filters, platforms: plat ? [plat] : undefined });
  };

  const activeCount =
    (filters.sources?.length || 0) +
    (filters.platforms?.length || 0) +
    (filters.event_types?.length || 0);

  return (
    <div className="bg-void-850 border border-void-700 px-3 py-2 flex items-center gap-3 flex-wrap">
      <div className="flex items-center gap-1 flex-wrap">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">src:</span>
        {sources.map((src) => {
          const cfg = sourceConfig[src];
          const active = filters.sources?.includes(src);
          return (
            <button
              key={src}
              onClick={() => toggleSource(src)}
              className={`px-2 py-0.5 text-[10px] font-mono uppercase transition-colors border ${
                active
                  ? `${cfg?.bg || 'bg-matrix-500/20'} ${cfg?.text || 'text-matrix-400'} ${cfg?.border || 'border-matrix-500/30'}`
                  : 'bg-void-800 text-gray-400 border-void-600 hover:text-white'
              }`}
              title={cfg?.name || src}
            >
              {(cfg?.name || src).replace(' Protections', ' Prot').replace(' Hunting', ' Hunt')}
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-1">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">plat:</span>
        <select
          value={filters.platforms?.[0] || ''}
          onChange={(e) => setPlatform(e.target.value || null)}
          className="bg-void-800 border border-void-600 text-xs text-gray-300 px-2 py-0.5 font-mono focus:outline-none focus:border-matrix-500/50 hover:text-white cursor-pointer"
        >
          <option value="">all platforms</option>
          {platforms.map((p) => (
            <option key={p.value} value={p.value}>
              {p.value} ({p.count})
            </option>
          ))}
        </select>
      </div>

      {activeCount > 0 && (
        <button
          onClick={() => setFilters({})}
          className="ml-auto text-[10px] font-mono text-gray-500 hover:text-breach-400 transition-colors uppercase tracking-wider"
        >
          [ clear ]
        </button>
      )}
    </div>
  );
}
