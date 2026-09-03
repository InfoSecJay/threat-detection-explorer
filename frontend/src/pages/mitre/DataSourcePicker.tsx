/**
 * Column picker for the coverage-by-data-source heatmap (#130).
 *
 * Two states: "top N by volume" (the default first paint, kept
 * readable) or an explicit set. The explicit set lives in the URL as
 * `ds=a,b,c` so a filtered view is shareable; column order follows the
 * order chosen. The picker itself is a chip row (selected columns,
 * each removable) plus a searchable checkbox popover over every data
 * source the corpus knows, ranked by rule volume.
 */

import { useEffect, useMemo, useRef, useState } from 'react';

export interface PickerOption {
  id: string;
  rules: number;
}

interface Props {
  /** Every data source, by volume. */
  available: PickerOption[];
  /** Explicit selection, or null for "top N". */
  selected: string[] | null;
  /** Columns currently shown (so the chip row is right in top-N mode too). */
  shown: PickerOption[];
  topN: number;
  onChange: (next: string[] | null) => void;
}

export function DataSourcePicker({ available, selected, shown, topN, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [needle, setNeedle] = useState('');
  const popover = useRef<HTMLDivElement>(null);

  // Close on outside click / Escape -- the popover is not modal.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (popover.current && !popover.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);

  const current = useMemo(() => selected ?? shown.map((s) => s.id), [selected, shown]);
  const currentSet = useMemo(() => new Set(current), [current]);
  const filtered = useMemo(() => {
    const n = needle.trim().toLowerCase();
    return n ? available.filter((a) => a.id.includes(n)) : available;
  }, [available, needle]);

  const toggle = (id: string) => {
    const next = currentSet.has(id) ? current.filter((c) => c !== id) : [...current, id];
    onChange(next);
  };
  const remove = (id: string) => onChange(current.filter((c) => c !== id));

  return (
    <div className="space-y-2" data-testid="ds-picker">
      <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
        <span className="text-gray-500">
          {selected ? `${selected.length} chosen` : `top ${topN} by rule volume`}
        </span>
        <div className="relative" ref={popover}>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="border border-void-600 text-gray-300 hover:text-matrix-400 hover:border-matrix-500/50 px-2 py-1"
            aria-expanded={open}
            data-testid="ds-picker-toggle"
          >
            [ choose sources ]
          </button>
          {open && (
            <div className="absolute z-20 mt-1 left-0 w-72 max-h-80 overflow-y-auto bg-void-900 border border-void-600 shadow-xl" data-testid="ds-picker-popover">
              <div className="sticky top-0 bg-void-900 p-2 border-b border-void-700">
                <input
                  autoFocus
                  value={needle}
                  onChange={(e) => setNeedle(e.target.value)}
                  placeholder="filter data sources..."
                  className="w-full bg-void-850 border border-void-700 text-gray-200 px-2 py-1 text-xs font-mono"
                  aria-label="Filter data sources"
                />
              </div>
              <ul className="p-1">
                {filtered.map((a) => (
                  <li key={a.id}>
                    <label className="flex items-center gap-2 px-2 py-1 hover:bg-void-800 cursor-pointer">
                      <input type="checkbox" checked={currentSet.has(a.id)} onChange={() => toggle(a.id)} className="accent-matrix-500" />
                      <span className="text-gray-200 flex-1 truncate">{a.id}</span>
                      <span className="text-gray-600 tabular-nums">{a.rules}</span>
                    </label>
                  </li>
                ))}
                {filtered.length === 0 && <li className="px-2 py-2 text-gray-600">no match</li>}
              </ul>
            </div>
          )}
        </div>
        <button type="button" onClick={() => onChange(available.map((a) => a.id))} className="text-gray-500 hover:text-matrix-400" data-testid="ds-picker-all">
          all ({available.length})
        </button>
        {selected && (
          <button type="button" onClick={() => onChange(null)} className="text-gray-500 hover:text-matrix-400" data-testid="ds-picker-reset">
            reset to top {topN}
          </button>
        )}
      </div>
      {selected && (
        <div className="flex flex-wrap gap-1" data-testid="ds-picker-chips">
          {selected.map((id) => (
            <span key={id} className="inline-flex items-center gap-1 bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono px-1.5 py-0.5">
              {id}
              <button type="button" onClick={() => remove(id)} className="text-cyan-500 hover:text-white" aria-label={`Remove ${id}`}>x</button>
            </span>
          ))}
          {selected.length === 0 && <span className="text-[10px] font-mono text-gray-600">no columns -- pick at least one, or reset</span>}
        </div>
      )}
    </div>
  );
}
