/** Hygiene threshold (#39). Cumulative bands: "at least N". The score
 * measures rule hygiene (metadata, mapping, docs, testability), not
 * detection accuracy. */

import type { FilterCtx } from './options';

export function HygieneSection({
  filters, onFiltersChange, bandCounts,
}: Omit<FilterCtx, 'toggle'> & { bandCounts: Record<string, number> }) {
  return (
    <div className="mt-2 px-2">
      <div className="flex gap-1" role="radiogroup" aria-label="Minimum hygiene score">
        {([
          { value: undefined, label: 'Any' },
          { value: 80, label: '80+' },
          { value: 60, label: '60+' },
          { value: 40, label: '40+' },
        ] as Array<{ value: number | undefined; label: string }>).map((opt) => {
          const active = filters.min_quality === opt.value;
          const count = opt.value === undefined ? undefined : bandCounts[String(opt.value)];
          return (
            <button
              key={opt.label}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => onFiltersChange({ ...filters, min_quality: opt.value, offset: 0 })}
              title={opt.value === undefined ? 'No hygiene threshold' : `Rules scoring at least ${opt.value}`}
              className={`flex-1 px-2 py-1 text-xs border rounded transition-colors ${
                active
                  ? 'bg-matrix-500/20 text-matrix-300 border-matrix-500/40'
                  : 'bg-void-900 text-gray-500 border-void-700 hover:text-gray-300'
              }`}
            >
              {opt.label}
              {count !== undefined && (
                <span className="ml-1 text-[10px] font-mono text-gray-600 tabular-nums">{count.toLocaleString()}</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
