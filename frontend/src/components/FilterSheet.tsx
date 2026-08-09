/**
 * FilterSheet — right-slide-in panel that houses the existing
 * FilterPanel. Replaces the persistent sidebar so the Detections
 * page gives its full width to results and the search bar.
 *
 * The sheet is discoverable via the "Filters" button (with an active-
 * count badge); the search bar is the primary interface for anyone
 * who knows what they want. Sheet + bar filters compose (AND) at the
 * API — SearchFilters carries both `q` (bar) and the array fields
 * (sheet) independently.
 *
 * Sheet is closed by: backdrop click, Escape, or the sheet's close X.
 */

import { useEffect } from 'react';
import { FilterPanel } from './FilterPanel';
import { countActiveFilters } from '../utils/filterUtils';
import type { SearchFilters } from '../types';

interface FilterSheetProps {
  filters: SearchFilters;
  onFiltersChange: (f: SearchFilters) => void;
  open: boolean;
  onClose: () => void;
}

export function FilterSheet({ filters, onFiltersChange, open, onClose }: FilterSheetProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    // Prevent background scroll while the sheet is open.
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  const active = countActiveFilters(filters);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        className={`fixed inset-0 z-40 bg-void-950/70 backdrop-blur-sm transition-opacity ${
          open ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        }`}
        aria-hidden="true"
      />
      {/* Panel */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Filters"
        className={`fixed top-0 right-0 bottom-0 z-50 w-full sm:w-[400px] bg-void-900 border-l border-void-700 shadow-[0_0_60px_rgba(0,0,0,0.6)] flex flex-col transition-transform ${
          open ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        <header className="flex items-center justify-between px-4 py-3 border-b border-void-700">
          <div className="flex items-baseline gap-3">
            <span className="w-1 h-4 bg-matrix-500" aria-hidden="true" />
            <h2 className="text-sm font-display font-bold text-white tracking-wider uppercase">
              Filters
            </h2>
            {active > 0 && (
              <span className="text-[10px] font-mono text-matrix-400 tabular-nums">
                {active} active
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {active > 0 && (
              <button
                onClick={() =>
                  onFiltersChange({
                    search: filters.search,
                    q: filters.q,
                    offset: 0,
                    limit: filters.limit,
                    sort_by: filters.sort_by,
                    sort_order: filters.sort_order,
                  })
                }
                className="text-[10px] font-mono text-gray-500 hover:text-breach-400 uppercase tracking-wider"
              >
                clear all
              </button>
            )}
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-white text-lg leading-none px-2"
              aria-label="Close filters"
              title="Close (Esc)"
            >
              ✕
            </button>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-4">
          <FilterPanel filters={filters} onFiltersChange={onFiltersChange} />
        </div>
      </aside>
    </>
  );
}
