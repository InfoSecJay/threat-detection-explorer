/**
 * FilterSheet — right-side filter panel with two behaviors:
 *
 *   floating (default): slide-in modal with backdrop + Esc-close +
 *     body-scroll-lock. Discoverable via the "Filters" button.
 *   pinned:  docked to the right, always visible. Parent adds
 *     equivalent right-padding so results stay readable. Pin
 *     toggles from the sheet header. State persists in
 *     localStorage. On <md viewports pinning is ignored (always
 *     floating) so narrow screens stay usable.
 *
 * Sheet + bar filters compose via AND at the API — SearchFilters
 * carries both `q` (bar) and the array fields (sheet) independently.
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
  pinned: boolean;
  onPinnedChange: (pinned: boolean) => void;
}

export function FilterSheet({
  filters,
  onFiltersChange,
  open,
  onClose,
  pinned,
  onPinnedChange,
}: FilterSheetProps) {
  // Modal behaviors (Esc + scroll-lock) only when floating + open.
  // Pinned mode is a static side panel; no keyboard trap, no
  // background scroll interference.
  useEffect(() => {
    if (pinned || !open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [pinned, open, onClose]);

  const active = countActiveFilters(filters);
  // When pinned, the sheet is always effectively "open" on md+
  // viewports. Track visibility separately so mobile still uses the
  // modal even when the desktop pref is pinned.
  const isVisible = pinned || open;

  return (
    <>
      {/* Backdrop — only in floating mode. Pinned mode has no
          backdrop so the user can still click through to results. */}
      {!pinned && (
        <div
          onClick={onClose}
          className={`fixed inset-0 z-40 bg-void-950/70 backdrop-blur-sm transition-opacity ${
            open ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
          }`}
          aria-hidden="true"
        />
      )}
      {/* Panel. In floating mode: fixed slide-in. In pinned mode
          on md+: fixed docked panel (parent adds right-padding so
          results stay visible). On <md, pinning is ignored so the
          panel behaves as a modal regardless of preference. */}
      <aside
        role={pinned ? 'complementary' : 'dialog'}
        aria-modal={pinned ? undefined : 'true'}
        aria-label="Filters"
        className={`fixed top-0 right-0 bottom-0 z-50 w-full sm:w-[380px] bg-void-900 border-l border-void-700 flex flex-col transition-transform ${
          pinned
            ? 'translate-x-full md:translate-x-0 md:shadow-none shadow-[0_0_60px_rgba(0,0,0,0.6)]'
            : `${open ? 'translate-x-0' : 'translate-x-full'} shadow-[0_0_60px_rgba(0,0,0,0.6)]`
        }`}
      >
        <header className="flex items-center justify-between px-4 py-3 border-b border-void-700 bg-void-900">
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
            {/* Pin/unpin toggle. Hidden on <md — pin makes no sense
                on narrow viewports where filters need to overlay. */}
            <button
              onClick={() => onPinnedChange(!pinned)}
              className={`hidden md:inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider leading-none px-1.5 py-1 border transition-colors ${
                pinned
                  ? 'text-matrix-400 border-matrix-500/40 bg-matrix-500/10 hover:bg-matrix-500/20'
                  : 'text-gray-500 border-void-700 hover:text-white hover:border-void-600'
              }`}
              aria-label={pinned ? 'Unpin filters (return to overlay mode)' : 'Pin filters (dock as a persistent side panel)'}
              title={pinned ? 'Unpin (overlay mode)' : 'Pin (dock as side panel)'}
            >
              <svg className={`w-3 h-3 ${pinned ? '' : 'rotate-45'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 5a2 2 0 012-2h6a2 2 0 012 2v6l3 3v2h-6v5l-1 1-1-1v-5H4v-2l3-3V5z" />
              </svg>
              {pinned ? 'Pinned' : 'Pin'}
            </button>
            {!pinned && (
              <button
                onClick={onClose}
                className="text-gray-500 hover:text-white text-lg leading-none px-2"
                aria-label="Close filters"
                title="Close (Esc)"
              >
                ✕
              </button>
            )}
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-4">
          <FilterPanel filters={filters} onFiltersChange={onFiltersChange} />
        </div>
      </aside>
      {/* Invisible presence marker so parent can query if pinned
          panel is currently visible (helps with keyboard shortcuts). */}
      {isVisible && <span className="sr-only">Filter panel visible</span>}
    </>
  );
}
