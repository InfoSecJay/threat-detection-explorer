/** Status + building-block filter (issue #26). */

import { CheckboxOption, FacetCount } from './CheckboxOption';
import { STATUS_OPTIONS, type FilterCtx } from './options';

export function StatusSection({
  filters, onFiltersChange, toggle, statusCounts, buildingBlockCount,
}: FilterCtx & { statusCounts: Record<string, number>; buildingBlockCount: number | undefined }) {
  return (
    <div className="space-y-1 mt-2">
      {STATUS_OPTIONS.filter((s) => statusCounts[s.value] !== undefined || filters.statuses?.includes(s.value)).map((s) => (
        <CheckboxOption
          key={s.value}
          checked={filters.statuses?.includes(s.value) || false}
          onChange={(checked) => toggle('statuses', s.value, checked)}
          label={s.label}
          color={s.color}
          title={s.hint}
          count={statusCounts[s.value]}
        />
      ))}
      <div className="pt-2 mt-1 border-t border-void-800">
        <div className="flex items-center justify-between px-2 mb-1">
          <span className="text-[11px] font-mono text-gray-500 uppercase" title="Building blocks feed other rules instead of alerting on their own">
            Building blocks
          </span>
          <FacetCount count={buildingBlockCount} />
        </div>
        <div className="flex gap-1 px-2" role="radiogroup" aria-label="Building blocks">
          {([
            { value: undefined, label: 'Any' },
            { value: true, label: 'Only' },
            { value: false, label: 'Hide' },
          ] as Array<{ value: boolean | undefined; label: string }>).map((opt) => {
            const active = filters.building_block === opt.value;
            return (
              <button
                key={opt.label}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => onFiltersChange({ ...filters, building_block: opt.value, offset: 0 })}
                className={`flex-1 px-2 py-1 text-xs border rounded transition-colors ${
                  active
                    ? 'bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/40'
                    : 'bg-void-900 text-gray-500 border-void-700 hover:text-gray-300'
                }`}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
