// Extracted from pages/Actors.tsx (#23). Behaviour unchanged.
import { useEffect, useRef, useState } from 'react';
import { clipSm } from '../../constants/style';

export function FacetSelect({
  label,
  options,
  selected,
  onChange,
  renderOption,
}: {
  label: string;
  options: Record<string, number>;
  selected: string[];
  onChange: (values: string[]) => void;
  renderOption?: (value: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  const entries = Object.entries(options);
  if (entries.length === 0 && selected.length === 0) return null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className={`px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-wider border transition-colors ${
          selected.length > 0
            ? 'bg-matrix-500/10 text-matrix-400 border-matrix-500/40'
            : 'bg-void-900 text-gray-400 border-void-700 hover:text-white'
        }`}
        style={clipSm}
      >
        {label}
        {selected.length > 0 && <span className="ml-1 tabular-nums">({selected.length})</span>}
        <span className="ml-1 text-gray-600">▾</span>
      </button>
      {open && (
        <div
          className="absolute z-20 mt-1 min-w-[220px] max-h-72 overflow-y-auto bg-void-900 border border-void-600 shadow-xl p-1"
        >
          {entries.map(([value, count]) => {
            const checked = selected.includes(value);
            return (
              <label
                key={value}
                className="flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-gray-300 hover:bg-void-800 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() =>
                    onChange(
                      checked ? selected.filter((v) => v !== value) : [...selected, value]
                    )
                  }
                  className="accent-matrix-500"
                />
                <span className="flex-1 truncate">{renderOption ? renderOption(value) : value}</span>
                <span className="text-gray-600 tabular-nums">{count}</span>
              </label>
            );
          })}
          {/* Selected values that fell out of the facet (count 0 under
              current filters) stay listed so they can be uchecked. */}
          {selected.filter((v) => !(v in options)).map((value) => (
            <label
              key={value}
              className="flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-gray-500 hover:bg-void-800 cursor-pointer"
            >
              <input
                type="checkbox"
                checked
                onChange={() => onChange(selected.filter((v) => v !== value))}
                className="accent-matrix-500"
              />
              <span className="flex-1 truncate">{renderOption ? renderOption(value) : value}</span>
              <span className="text-gray-600 tabular-nums">0</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
