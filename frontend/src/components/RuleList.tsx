/** Catalog result table: selection, inline previews, sortable columns
 * and paging. Cells and helpers live in components/rulelist/. */

import { useEffect, useState } from 'react';
import type { Detection, SearchFilters } from '../types';
import { clipMd, clipLg } from '../constants/style';
import { sortOptions } from './rulelist/format';
import { RuleCard } from './rulelist/RuleCard';
import { SortableTh } from './rulelist/SortableTh';
import { RuleRow } from './rulelist/RuleRow';
import { Pagination } from './rulelist/Pagination';

interface RuleListProps {
  detections: Detection[];
  total: number;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  isLoading?: boolean;
  enableSelection?: boolean;
  onExportSelected?: (ids: string[]) => void;
}

export function RuleList({
  detections,
  total,
  filters,
  onFiltersChange,
  isLoading,
  enableSelection = true,
  onExportSelected,
}: RuleListProps) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  // Rows expanded inline to show query logic / references / FP notes.
  // Keeps the result list and scroll position intact — previously
  // scanning 25 rules meant 25 detail-page round trips.
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  // Keep the selection scoped to rows the user can see. Without this,
  // paging or re-filtering left "25 SELECTED" (and a checked header
  // box) over a page with nothing ticked, and Export shipped rules
  // that were no longer on screen.
  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const visible = new Set(detections.map((d) => d.id));
      const kept = new Set([...prev].filter((id) => visible.has(id)));
      return kept.size === prev.size ? prev : kept;
    });
  }, [detections]);

  const limit = filters.limit || 25;
  const offset = filters.offset || 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit);

  // Selection handlers
  const toggleSelection = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const selectAll = () => {
    const allIds = detections.map((d) => d.id);
    setSelectedIds(new Set(allIds));
  };

  const clearSelection = () => {
    setSelectedIds(new Set());
  };

  const toggleExpanded = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handlePageChange = (page: number) => {
    onFiltersChange({ ...filters, offset: (page - 1) * limit });
  };

  const handleSort = (field: string) => {
    const newOrder =
      filters.sort_by === field && filters.sort_order === 'asc' ? 'desc' : 'asc';
    onFiltersChange({ ...filters, sort_by: field, sort_order: newOrder });
  };

  const handleQuickSort = (value: string) => {
    const [sort_by, sort_order] = value.split(':');
    onFiltersChange({ ...filters, sort_by, sort_order: sort_order as 'asc' | 'desc' });
  };

  const currentSortValue = `${filters.sort_by || 'title'}:${filters.sort_order || 'asc'}`;
  const sortProps = { sortBy: filters.sort_by, sortOrder: filters.sort_order, onSort: handleSort };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 border-2 border-matrix-500/30 rounded-full"></div>
          <div className="absolute inset-0 border-2 border-transparent border-t-matrix-500 rounded-full animate-spin"></div>
        </div>
        <p className="mt-4 text-sm font-mono text-gray-500">LOADING_DETECTIONS...</p>
      </div>
    );
  }

  if (detections.length === 0) {
    return (
      <div
        className="text-center py-12 bg-void-850 border border-void-700"
        style={clipLg}
      >
        <svg className="w-12 h-12 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p className="text-gray-400 font-display">NO DETECTIONS FOUND</p>
        <p className="text-sm text-gray-500 mt-2 font-mono">
          Try adjusting filters or sync repositories
        </p>
      </div>
    );
  }

  return (
    <div>
      {/* Header with count and controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-4">
          <p className="text-sm font-mono text-gray-500">
            <span className="text-gray-600">[</span>
            {offset + 1}-{Math.min(offset + limit, total)}
            <span className="text-gray-600">]</span>
            <span className="text-gray-600 mx-1">/</span>
            <span className="text-matrix-500">{total.toLocaleString()}</span>
          </p>

          {enableSelection && selectedIds.size > 0 && (
            <div className="flex items-center gap-3 px-3 py-1.5 bg-matrix-500/10 border border-matrix-500/30">
              <span className="text-xs font-mono text-matrix-500">
                {selectedIds.size} SELECTED
              </span>
              <button
                onClick={clearSelection}
                className="text-xs font-mono text-gray-400 hover:text-white transition-colors"
              >
                CLEAR
              </button>
              {onExportSelected && selectedIds.size >= 1 && (
                <button
                  onClick={() => onExportSelected(Array.from(selectedIds))}
                  className="px-3 py-1 bg-pulse-500 text-void-950 text-xs font-display font-semibold uppercase hover:bg-pulse-400 transition-colors"
                >
                  EXPORT
                </button>
              )}
            </div>
          )}
        </div>

        {/* flex-wrap + capped select width: at 375px these controls
            used to run past the viewport edge (teardown F04/S1.8). */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-2">
            <label className="text-xs font-mono text-gray-500">SORT:</label>
            <select
              value={currentSortValue}
              onChange={(e) => handleQuickSort(e.target.value)}
              className="text-xs bg-void-850 border border-void-700 text-white px-2 py-1.5 focus:ring-matrix-500/50 focus:border-matrix-500/50 max-w-[42vw]"
            >
              {sortOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs font-mono text-gray-500">LIMIT:</label>
            <select
              value={limit}
              onChange={(e) =>
                onFiltersChange({ ...filters, limit: parseInt(e.target.value), offset: 0 })
              }
              className="text-xs bg-void-850 border border-void-700 text-white px-2 py-1.5 focus:ring-matrix-500/50 focus:border-matrix-500/50"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div
        className="bg-void-850 border border-void-700 overflow-hidden"
        style={clipMd}
      >
        {/* Card list under 640px (teardown R18 / #116): the table's ten
            columns leave only Title on a phone screen. */}
        <div className="sm:hidden divide-y divide-void-800">
          {detections.map((detection) => (
            <RuleCard key={detection.id} detection={detection} />
          ))}
        </div>
        <div className="hidden sm:block overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-void-900">
              <tr>
                {enableSelection && (
                  <th scope="col" className="px-3 py-3 text-left w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === detections.length && selectedIds.size > 0}
                      onChange={(e) => (e.target.checked ? selectAll() : clearSelection())}
                      className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
                      title="Select all on page"
                    />
                  </th>
                )}
                {/* Expand-chevron column — no header label */}
                <th scope="col" className="px-2 py-3 w-8" aria-label="Expand row" />
                <SortableTh {...sortProps} field="title" label="Title" pad="px-4" />
                <SortableTh {...sortProps} field="source" label="Source"
                  title="Source repository · query language. Sorts by source; use the SORT dropdown for language ordering." />
                <SortableTh {...sortProps} field="severity" label="Severity" />
                <SortableTh {...sortProps} field="platforms" label="Platform"
                  title="Sort by first platform (alphabetical)" />
                <SortableTh {...sortProps} field="data_sources" label="Data Source"
                  title="Sort by first data source (alphabetical)" />
                <SortableTh {...sortProps} field="event_types" label="Event Type"
                  title="Sort by first event type (alphabetical)" />
                <SortableTh {...sortProps} field="rule_created_date" label="Created" />
                <SortableTh {...sortProps} field="quality_score" label="Completeness"
                  title="Metadata completeness: metadata, ATT&CK mapping, specificity, docs, testability. Measures documentation quality, not detection accuracy." />
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {detections.map((detection) => (
                <RuleRow
                  key={detection.id}
                  detection={detection}
                  enableSelection={enableSelection}
                  selected={selectedIds.has(detection.id)}
                  expanded={expandedIds.has(detection.id)}
                  onToggleSelect={(e) => toggleSelection(detection.id, e)}
                  onToggleExpand={(e) => toggleExpanded(detection.id, e)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>


      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={handlePageChange} />
      )}
    </div>
  );
}
