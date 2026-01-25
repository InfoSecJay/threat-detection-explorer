import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import type { Detection, SearchFilters } from '../types';
import { useMitre } from '../contexts/MitreContext';

interface RuleListProps {
  detections: Detection[];
  total: number;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  isLoading?: boolean;
  enableSelection?: boolean;
}

// Color mappings
const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-breach-500/10', text: 'text-breach-400', border: 'border-breach-500/30' },
  high: { bg: 'bg-threat-500/10', text: 'text-threat-400', border: 'border-threat-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-pulse-500/10', text: 'text-pulse-400', border: 'border-pulse-500/30' },
  unknown: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
};

const sourceColors: Record<string, string> = {
  sigma: '#a855f7',
  elastic: '#3b82f6',
  splunk: '#f97316',
  sublime: '#ec4899',
  elastic_protections: '#06b6d4',
  lolrmm: '#22c55e',
};

const statusColors: Record<string, { bg: string; text: string; border: string }> = {
  stable: { bg: 'bg-pulse-500/10', text: 'text-pulse-400', border: 'border-pulse-500/30' },
  experimental: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  deprecated: { bg: 'bg-breach-500/10', text: 'text-breach-400', border: 'border-breach-500/30' },
  unknown: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
};

const sourceLabels: Record<string, string> = {
  sigma: 'SIGMA',
  elastic: 'ELASTIC',
  splunk: 'SPLUNK',
  sublime: 'SUBLIME',
  elastic_protections: 'EL_PROTECT',
  lolrmm: 'LOLRMM',
};

// Sort options
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
}: RuleListProps) {
  const { getTacticName } = useMitre();
  const navigate = useNavigate();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const limit = filters.limit || 50;
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
      } else if (next.size < 6) {
        next.add(id);
      }
      return next;
    });
  };

  const selectAll = () => {
    const allIds = detections.slice(0, 6).map((d) => d.id);
    setSelectedIds(new Set(allIds));
  };

  const clearSelection = () => {
    setSelectedIds(new Set());
  };

  const handleCompareSelected = () => {
    const ids = Array.from(selectedIds);
    navigate(`/compare/side-by-side?ids=${ids.join(',')}`);
  };

  const isSelected = (id: string) => selectedIds.has(id);
  const canSelect = selectedIds.size < 6;

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
        style={{
          clipPath: 'polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 16px 100%, 0 calc(100% - 16px))',
        }}
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
              {selectedIds.size >= 2 && (
                <button
                  onClick={handleCompareSelected}
                  className="px-3 py-1 bg-matrix-500 text-void-950 text-xs font-display font-semibold uppercase hover:bg-matrix-400 transition-colors"
                >
                  COMPARE
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
        style={{
          clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
        }}
      >
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-void-900">
              <tr>
                {enableSelection && (
                  <th className="px-3 py-3 text-left w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === Math.min(6, detections.length) && selectedIds.size > 0}
                      onChange={() => selectedIds.size > 0 ? clearSelection() : selectAll()}
                      className="w-3.5 h-3.5 rounded-sm bg-void-900 border-void-600 text-matrix-500 focus:ring-matrix-500/50"
                      title="Select all (max 6)"
                    />
                  </th>
                )}
                <th
                  className="px-4 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('title')}
                >
                  Title <SortIndicator field="title" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('source')}
                >
                  Source <SortIndicator field="source" />
                </th>
                <th className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider">
                  Lang
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('severity')}
                >
                  Severity <SortIndicator field="severity" />
                </th>
                <th className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider">
                  Tactics
                </th>
                <th className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider">
                  Techniques
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('rule_modified_date')}
                >
                  Modified <SortIndicator field="rule_modified_date" />
                </th>
                <th
                  className="px-3 py-3 text-left text-xs font-display font-semibold text-gray-500 uppercase tracking-wider cursor-pointer hover:text-matrix-500 transition-colors"
                  onClick={() => handleSort('status')}
                >
                  Status <SortIndicator field="status" />
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-void-800">
              {detections.map((detection) => {
                const sevColors = severityColors[detection.severity] || severityColors.unknown;
                const statColors = statusColors[detection.status] || statusColors.unknown;
                const sourceColor = sourceColors[detection.source] || '#6b7280';

                return (
                  <tr
                    key={detection.id}
                    className={`hover:bg-void-800/50 cursor-pointer transition-colors ${
                      isSelected(detection.id) ? 'bg-matrix-500/5' : ''
                    }`}
                    onClick={() => window.location.href = `/detections/${detection.id}`}
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
                    <td className="px-4 py-3 max-w-md">
                      <Link
                        to={`/detections/${detection.id}`}
                        className="text-sm font-medium text-matrix-500 hover:text-matrix-400 transition-colors"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {detection.title}
                      </Link>
                      {detection.description && (
                        <p className="text-xs text-gray-500 mt-1 line-clamp-1">
                          {detection.description}
                        </p>
                      )}
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
                      </span>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span className="px-2 py-1 bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 text-xs font-mono uppercase">
                        {detection.language || '?'}
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
                      <div className="flex flex-wrap gap-1 max-w-[180px]">
                        {detection.mitre_tactics.slice(0, 2).map((tactic) => (
                          <span
                            key={tactic}
                            className="px-1.5 py-0.5 text-xs bg-void-700 text-gray-300 border border-void-600"
                            title={tactic}
                          >
                            {getTacticName(tactic)}
                          </span>
                        ))}
                        {detection.mitre_tactics.length > 2 && (
                          <span
                            className="text-xs text-gray-500"
                            title={detection.mitre_tactics.map(t => `${t}: ${getTacticName(t)}`).join('\n')}
                          >
                            +{detection.mitre_tactics.length - 2}
                          </span>
                        )}
                        {detection.mitre_tactics.length === 0 && (
                          <span className="text-xs text-gray-600">-</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-1 max-w-[120px]">
                        {detection.mitre_techniques.slice(0, 2).map((tech) => (
                          <span
                            key={tech}
                            className="px-1.5 py-0.5 bg-matrix-500/10 text-matrix-500 text-xs font-mono border border-matrix-500/20"
                            title={tech}
                          >
                            {tech}
                          </span>
                        ))}
                        {detection.mitre_techniques.length > 2 && (
                          <span
                            className="text-xs text-gray-500"
                            title={detection.mitre_techniques.join(', ')}
                          >
                            +{detection.mitre_techniques.length - 2}
                          </span>
                        )}
                        {detection.mitre_techniques.length === 0 && (
                          <span className="text-xs text-gray-600">-</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className="text-xs font-mono text-gray-400"
                        title={formatDate(detection.rule_modified_date)}
                      >
                        {formatRelativeDate(detection.rule_modified_date)}
                      </span>
                    </td>
                    <td className="px-3 py-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 text-xs font-mono font-medium border ${statColors.bg} ${statColors.text} ${statColors.border}`}
                      >
                        {detection.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
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
