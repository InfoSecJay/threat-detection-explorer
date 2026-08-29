/** MITRE tactic checkboxes, first five by default with a show-all toggle. */

import { useState } from 'react';
import { CheckboxOption } from './CheckboxOption';
import type { FilterCtx } from './options';

export function TacticsSection({
  filters, toggle, options, counts,
}: Omit<FilterCtx, 'onFiltersChange'> & {
  options: Array<{ value: string; label: string }>;
  counts: Record<string, number>;
}) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? options : options.slice(0, 5);
  return (
    <div className="mt-2">
      <div className="space-y-1">
        {visible.map((tactic) => (
          <CheckboxOption
            key={tactic.value}
            checked={filters.mitre_tactics?.includes(tactic.value) || false}
            onChange={(checked) => toggle('mitre_tactics', tactic.value, checked)}
            label={tactic.label}
            title={tactic.value}
            labelClass="truncate"
            count={counts[tactic.value]}
          />
        ))}
      </div>
      {options.length > 5 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-2 text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
        >
          {showAll ? '- SHOW LESS' : `+ ${options.length - 5} MORE`}
        </button>
      )}
    </div>
  );
}
