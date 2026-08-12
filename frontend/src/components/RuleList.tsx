import { Fragment, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { sourceColors, sourceLabelsShort as sourceLabels } from '../constants/sources';
import type { Detection, SearchFilters } from '../types';
import { clipMd, clipLg } from '../constants/style';

interface RuleListProps {
  detections: Detection[];
  total: number;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  isLoading?: boolean;
  enableSelection?: boolean;
  onExportSelected?: (ids: string[]) => void;
}

// Color mappings
const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-breach-500/10', text: 'text-breach-400', border: 'border-breach-500/30' },
  high: { bg: 'bg-threat-500/10', text: 'text-threat-400', border: 'border-threat-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-pulse-500/10', text: 'text-pulse-400', border: 'border-pulse-500/30' },
  unknown: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
};

// Sort options -- mirrors the clickable column headers below. Any
// field listed here must also appear in the backend
// _apply_sorting sort_columns map or the sort silently falls back
// to Title.
const sortOptions = [
  { value: 'title:asc', label: 'Title (A-Z)' },
  { value: 'title:desc', label: 'Title (Z-A)' },
  { value: 'severity:desc', label: 'Severity (High to Low)' },
  { value: 'severity:asc', label: 'Severity (Low to High)' },
  { value: 'rule_created_date:desc', label: 'Created (Newest)' },
  { value: 'rule_created_date:asc', label: 'Created (Oldest)' },
  { value: 'rule_modified_date:desc', label: 'Modified (Newest)' },
  { value: 'rule_modified_date:asc', label: 'Modified (Oldest)' },
  { value: 'source:asc', label: 'Source (A-Z)' },
  { value: 'source:desc', label: 'Source (Z-A)' },
  { value: 'language:asc', label: 'Language (A-Z)' },
  { value: 'language:desc', label: 'Language (Z-A)' },
  { value: 'platforms:asc', label: 'Platform (A-Z)' },
  { value: 'platforms:desc', label: 'Platform (Z-A)' },
  { value: 'data_sources:asc', label: 'Data Source (A-Z)' },
  { value: 'data_sources:desc', label: 'Data Source (Z-A)' },
  { value: 'event_types:asc', label: 'Event Type (A-Z)' },
  { value: 'event_types:desc', label: 'Event Type (Z-A)' },
];

function formatRelativeDate(dateStr: string | null): string {
  if (!dateStr) return '-';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '-';

  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays}d`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)}w`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo`;
  return `${Math.floor(diffDays / 365)}y`;
}

// Cap visible tags per cell; overflow collapses into a "+N" tag
const MAX_VISIBLE_TAGS = 3;

function TagList({ items, colorClass }: { items: string[] | null | undefined; colorClass: string }) {
  if (!items || items.length === 0) {
    return <span className="text-xs text-gray-600">-</span>;
  }

  const visible = items.slice(0, MAX_VISIBLE_TAGS);
  const hidden = items.slice(MAX_VISIBLE_TAGS);

  return (
    <div className="flex flex-wrap gap-1">
      {visible.map((item) => (
        <span
          key={item}
          className={`px-1.5 py-0.5 text-xs font-mono border ${
            item === 'unknown'
              ? 'bg-gray-500/15 text-gray-500 border-gray-500/30 italic'
              : colorClass
          }`}
        >
          {item}
        </span>
      ))}
      {hidden.length > 0 && (
        <span
          className="px-1.5 py-0.5 text-xs font-mono border bg-gray-500/10 text-gray-400 border-gray-500/30"
          title={hidden.join(', ')}
        >
          +{hidden.length}
        </span>
      )}
    </div>
  );
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return '-';
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
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
  const navigate = useNavigate();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  // Rows expanded inline to show query logic / references / FP notes.
  // Keeps the result list and scroll position intact — previously
  // scanning 25 rules meant 25 detail-page round trips.
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

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

  const isSelected = (id: string) => selectedIds.has(id);
  const canSelect = true; // No limit on selection

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

  const SortIndicator = ({ field }: { field: string }) => {
    if (filters.sort_by !== field) return null;
    return (
      <span className="ml-1 text-matrix-500">
        {filters.sort_order === 'asc' ? '↑' : '↓'}
      </span>
    );
  };

  // Generate visible page numbers
  const getVisiblePages = () => {
    const pages: (number | string)[] = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible + 2) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) pages.push('...');
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) pages.push(i);
      if (currentPage < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

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

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <label className="text-xs font-mono text-gray-500">SORT:</label>
            <select
              value={currentSortValue}
              onChange={(e) => handleQuickSort(e.target.value)}
              className="text-xs bg-void-850 border border-void-700 text-white px-2 py-1.5 focus:ring-matrix-500/50 focus:border-matrix-500/50"
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
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-void-900">
              <tr>
                {enableSelection && (
                  <th className="px-3 py-3 text-left w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === detections.length && selectedIds.size > 0}
                      onChange={() => selectedIds.size > 0 ? clearSelection() : selectAll()}
                      className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
                      title="Select all on page"
                    />
                  </th>
                )}
                {/* Expand-chevron column — no header label */}
                <th className="px-2 py-3 w-8" aria-label="Expand row" />
                <th
                  className="px-4 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('title')}
                >
                  Title <SortIndicator field="title" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('source')}
                  title="Source repository · query language. Sorts by source; use the SORT dropdown for language ordering."
                >
                  Source <SortIndicator field="source" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('severity')}
                >
                  Severity <SortIndicator field="severity" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('platforms')}
                  title="Sort by first platform (alphabetical)"
                >
                  Platform <SortIndicator field="platforms" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('data_sources')}
                  title="Sort by first data source (alphabetical)"
                >
                  Data Source <SortIndicator field="data_sources" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('event_types')}
                  title="Sort by first event type (alphabetical)"
                >
                  Event Type <SortIndicator field="event_types" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('rule_created_date')}
                >
                  Created <SortIndicator field="rule_created_date" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('rule_modified_date')}
                >
                  Modified <SortIndicator field="rule_modified_date" />
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {detections.map((detection) => {
                const sevColors = severityColors[detection.severity] || severityColors.unknown;
                const sourceColor = sourceColors[detection.source] || '#6b7280';
                const expanded = expandedIds.has(detection.id);
                // SOURCE · LANG merged chip. The language suffix only
                // carries information when it's a real value — lolrmm
                // and freshly-ingested rules have language "unknown".
                const lang =
                  detection.language && detection.language !== 'unknown'
                    ? detection.language.toUpperCase()
                    : null;

                return (
                  <Fragment key={detection.id}>
                  <tr
                    className={`hover:bg-void-800/50 cursor-pointer transition-colors ${
                      isSelected(detection.id) ? 'bg-matrix-500/5' : ''
                    }`}
                    onClick={() => navigate(`/detections/${detection.id}`)}
                  >
                    {enableSelection && (
                      <td className="px-3 py-3" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected(detection.id)}
                          onChange={() => {}}
                          onClick={(e) => toggleSelection(detection.id, e)}
                          disabled={!isSelected(detection.id) && !canSelect}
                          className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50 disabled:opacity-50"
                        />
                      </td>
                    )}
                    <td className="px-2 py-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={(e) => toggleExpanded(detection.id, e)}
                        className="p-1 text-gray-500 hover:text-matrix-500 transition-colors"
                        aria-expanded={expanded}
                        aria-label={expanded ? 'Collapse rule preview' : 'Expand rule preview'}
                        title={expanded ? 'Collapse preview' : 'Preview query logic, references, FP notes'}
                      >
                        <svg
                          className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    </td>
                    <td className="px-4 py-3 max-w-md">
                      <Link
                        to={`/detections/${detection.id}`}
                        className="text-sm font-medium text-matrix-500 hover:text-matrix-400 transition-colors"
                        onClick={(e) => e.stopPropagation()}
                        title={detection.description || undefined}
                      >
                        {detection.title}
                      </Link>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className="px-2 py-1 text-xs font-mono font-medium border"
                        style={{
                          backgroundColor: `${sourceColor}15`,
                          color: sourceColor,
                          borderColor: `${sourceColor}40`,
                        }}
                      >
                        {sourceLabels[detection.source] || detection.source.toUpperCase()}
                        {lang && <span className="opacity-60"> · {lang}</span>}
                      </span>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 text-xs font-mono font-medium border ${sevColors.bg} ${sevColors.text} ${sevColors.border}`}
                      >
                        {detection.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <TagList
                        items={detection.platforms}
                        colorClass="bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
                      />
                    </td>
                    <td className="px-3 py-3">
                      <TagList
                        items={detection.data_sources}
                        colorClass="bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                      />
                    </td>
                    <td className="px-3 py-3">
                      <TagList
                        items={detection.event_types}
                        colorClass="bg-orange-500/10 text-orange-300 border-orange-500/30"
                      />
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className="text-xs font-mono text-gray-400"
                        title={formatDate(detection.rule_created_date)}
                      >
                        {formatRelativeDate(detection.rule_created_date)}
                      </span>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className="text-xs font-mono text-gray-400"
                        title={formatDate(detection.rule_modified_date)}
                      >
                        {formatRelativeDate(detection.rule_modified_date)}
                      </span>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="bg-void-900/60">
                      <td colSpan={enableSelection ? 10 : 9} className="px-6 py-4">
                        <div className="space-y-4">
                          {/* Query logic */}
                          <div>
                            <div className="flex items-center gap-2 mb-1.5">
                              <span className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider">
                                Detection Logic
                              </span>
                              {lang && (
                                <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 text-[10px] font-mono">
                                  {lang}
                                </span>
                              )}
                            </div>
                            <pre className="p-3 bg-void-950 border border-void-700 text-xs font-mono text-gray-300 whitespace-pre-wrap break-words max-h-72 overflow-y-auto">
                              {detection.detection_logic || 'No query logic available'}
                            </pre>
                          </div>

                          {/* References */}
                          {detection.references && detection.references.length > 0 && (
                            <div>
                              <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                                References
                              </div>
                              <ul className="space-y-1">
                                {detection.references.map((ref) => (
                                  <li key={ref} className="text-xs font-mono truncate">
                                    <a
                                      href={ref}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-cyan-400 hover:text-cyan-300 transition-colors"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      {ref}
                                    </a>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* False positives */}
                          {detection.false_positives && detection.false_positives.length > 0 && (
                            <div>
                              <div className="text-[10px] font-display font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                                False Positives
                              </div>
                              <ul className="space-y-1">
                                {detection.false_positives.map((fp, i) => (
                                  <li key={i} className="text-xs text-gray-400 flex gap-2">
                                    <span className="text-yellow-500/70 shrink-0">!</span>
                                    <span>{fp}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          <Link
                            to={`/detections/${detection.id}`}
                            className="inline-block text-xs font-mono text-matrix-500 hover:text-matrix-400 transition-colors"
                          >
                            VIEW FULL RULE -&gt;
                          </Link>
                        </div>
                      </td>
                    </tr>
                  )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <div className="text-sm font-mono text-gray-500">
            PAGE <span className="text-matrix-500">{currentPage}</span> / {totalPages}
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1.5 border border-void-700 text-xs font-display text-gray-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-void-800 hover:border-matrix-500/30 transition-all"
            >
              PREV
            </button>
            {getVisiblePages().map((page, idx) => (
              typeof page === 'number' ? (
                <button
                  key={idx}
                  onClick={() => handlePageChange(page)}
                  className={`px-3 py-1.5 border text-xs font-mono transition-all ${
                    page === currentPage
                      ? 'bg-matrix-500/10 text-matrix-500 border-matrix-500/30'
                      : 'border-void-700 text-gray-300 hover:bg-void-800 hover:border-matrix-500/30'
                  }`}
                >
                  {page}
                </button>
              ) : (
                <span key={idx} className="px-2 text-gray-600">
                  {page}
                </span>
              )
            ))}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1.5 border border-void-700 text-xs font-display text-gray-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-void-800 hover:border-matrix-500/30 transition-all"
            >
              NEXT
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
