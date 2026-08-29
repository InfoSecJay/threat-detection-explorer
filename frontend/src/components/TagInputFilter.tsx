import { useMemo, useRef, useState } from 'react';

/**
 * Reusable tag / chip filter input.
 *
 * Used for the five freeform filter inputs on the Detections page
 * (Log Sources, Event IDs, Process Names, API Actions, MITRE
 * Techniques). Each follows the same pattern — user types a value,
 * hits Enter, it becomes a removable chip — so DRYing this up
 * removed ~200 lines of copy-pasted markup from FilterPanel.
 *
 * Optional `suggestions` prop turns it into an autocomplete: typing
 * filters the suggestion list live, Enter adds the top match (or the
 * literal input if no match), clicking a suggestion adds it too.
 *
 * Values are stored/compared case-insensitively via `normalize` prop
 * (used for MITRE technique IDs which must be uppercase, and for
 * lowercased log sources).
 */

export type Suggestion = {
  /** Canonical value — what goes into the filter. */
  value: string;
  /** Optional longer label shown to the user. */
  label?: string;
};

interface TagInputFilterProps {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  /** When provided, render an autocomplete dropdown. */
  suggestions?: Suggestion[];
  /** Lowercase / uppercase / etc the entered value before comparing and storing. */
  normalize?: (raw: string) => string;
  /** Chip color accent — matches the visual language of the filter. */
  accent?: 'matrix' | 'purple' | 'cyan' | 'emerald' | 'orange';
  /** Cap suggestions dropdown length. Default 8. */
  maxSuggestions?: number;
}

const ACCENT_CLASSES: Record<NonNullable<TagInputFilterProps['accent']>, string> = {
  matrix: 'bg-matrix-500/10 text-matrix-500 border-matrix-500/30',
  purple: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
  cyan: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
  emerald: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  orange: 'bg-orange-500/10 text-orange-300 border-orange-500/30',
};

export function TagInputFilter({
  values,
  onChange,
  placeholder,
  suggestions,
  normalize,
  accent = 'matrix',
  maxSuggestions = 8,
}: TagInputFilterProps) {
  const [query, setQuery] = useState('');
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const normalizedValues = useMemo(() => new Set(values), [values]);

  const matches = useMemo(() => {
    if (!suggestions || !query.trim()) return [] as Suggestion[];
    const q = query.toLowerCase();
    return suggestions
      .filter(
        (s) =>
          !normalizedValues.has(s.value) &&
          (s.value.toLowerCase().includes(q) ||
            (s.label && s.label.toLowerCase().includes(q))),
      )
      .slice(0, maxSuggestions);
  }, [suggestions, query, normalizedValues, maxSuggestions]);

  const add = (raw: string) => {
    const cleaned = (normalize ? normalize(raw) : raw).trim();
    if (!cleaned || normalizedValues.has(cleaned)) return;
    onChange([...values, cleaned]);
    setQuery('');
    // Keep focus for rapid multi-entry.
    inputRef.current?.focus();
  };

  const remove = (value: string) => {
    onChange(values.filter((v) => v !== value));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      // If a suggestion is on top of the list, pick it; otherwise use
      // whatever the user typed literally.
      const pick = matches[0]?.value ?? query;
      if (pick) add(pick);
    } else if (e.key === 'Backspace' && !query && values.length > 0) {
      // Backspace on empty input removes the last chip — feels natural
      // after typing a few techniques in a row.
      onChange(values.slice(0, -1));
    }
  };

  const chipCls = ACCENT_CLASSES[accent];

  return (
    <div className="relative">
      <input
        ref={inputRef}
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={handleKeyDown}
        onFocus={() => setFocused(true)}
        onBlur={() => setTimeout(() => setFocused(false), 150)}
        placeholder={placeholder}
        className="w-full px-3 py-2 bg-void-900 border border-void-700 text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-matrix-500/50 focus:border-matrix-500/50"
      />

      {focused && matches.length > 0 && (
        <div className="absolute z-10 top-full left-0 right-0 mt-1 bg-void-900 border border-void-700 shadow-lg max-h-64 overflow-y-auto">
          {matches.map((s) => (
            <button
              key={s.value}
              onMouseDown={() => add(s.value)}
              className="w-full text-left px-3 py-1.5 text-sm hover:bg-void-800 text-gray-300 flex items-center justify-between gap-2"
            >
              <span className="font-mono text-matrix-500 shrink-0">{s.value}</span>
              {s.label && (
                <span className="text-xs text-gray-500 truncate">{s.label}</span>
              )}
            </button>
          ))}
        </div>
      )}

      {values.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-2">
          {values.map((v) => (
            <span
              key={v}
              className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-mono border ${chipCls}`}
            >
              {v}
              <button
                onClick={() => remove(v)}
                className="ml-0.5 opacity-70 hover:opacity-100"
                aria-label={`Remove ${v}`}
              >
                ✕
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
