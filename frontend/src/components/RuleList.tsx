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

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const sourceColors: Record<string, string> = {
  sigma: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  elastic: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  splunk: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  sublime: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  elastic_protections: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  lolrmm: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-500/20 text-green-400 border-green-500/30',
  experimental: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  deprecated: 'bg-red-500/20 text-red-400 border-red-500/30',
  unknown: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const sourceLabels: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Protect',
  lolrmm: 'LOLRMM',
};

const tacticColors: Record<string, string> = {
  TA0001: 'bg-red-500/20 text-red-400 border-red-500/30',
  TA0002: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  TA0003: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  TA0004: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  TA0005: 'bg-lime-500/20 text-lime-400 border-lime-500/30',
  TA0006: 'bg-green-500/20 text-green-400 border-green-500/30',
  TA0007: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  TA0008: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
  TA0009: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  TA0010: 'bg-sky-500/20 text-sky-400 border-sky-500/30',
  TA0011: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  TA0040: 'bg-violet-500/20 text-violet-400 border-violet-500/30',
  TA0042: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  TA0043: 'bg-fuchsia-500/20 text-fuchsia-400 border-fuchsia-500/30',
};

// Sort options for quick access
const sortOptions = [
  { value: 'title:asc', label: 'Title (A-Z)' },
  { value: 'title:desc', label: 'Title (Z-A)' },
  { value: 'severity:desc', label: 'Severity (High to Low)' },
  { value: 'severity:asc', label: 'Severity (Low to High)' },
  { value: 'rule_created_date:desc', label: 'Rule Created (Newest)' },
  { value: 'rule_created_date:asc', label: 'Rule Created (Oldest)' },
  { value: 'rule_modified_date:desc', label: 'Rule Modified (Newest)' },
  { value: 'rule_modified_date:asc', label: 'Rule Modified (Oldest)' },
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
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
  return `${Math.floor(diffDays / 365)} years ago`;
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
      <span className="ml-1 text-cyan-400">
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
      <div className="text-center py-8">
        <div className="animate-spin h-8 w-8 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-2 text-gray-400">Loading detections...</p>
      </div>
    );
  }

  if (detections.length === 0) {
    return (
      <div className="text-center py-8 bg-cyber-850 rounded-lg border border-cyber-700">
        <p className="text-gray-400">No detections found.</p>
        <p className="text-sm text-gray-500 mt-1">
          Try adjusting your filters or syncing repositories first.
        </p>
      </div>
    );
  }

  return (
    <div>
      {/* Header with count and sort */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-4">
          <p className="text-sm text-gray-400">
            Showing {offset + 1}-{Math.min(offset + limit, total)} of{' '}
            {total.toLocaleString()} detections
          </p>
          {enableSelection && selectedIds.size > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-cyan-400">
                {selectedIds.size} selected
              </span>
              <button
                onClick={clearSelection}
                className="text-xs text-gray-400 hover:text-white"
              >
                Clear
              </button>
              {selectedIds.size >= 2 && (
                <button
                  onClick={handleCompareSelected}
                  className="px-3 py-1 bg-gradient-to-r from-cyan-500 to-blue-500 text-white text-xs rounded hover:from-cyan-400 hover:to-blue-400 transition-all"
                >
                  Compare Selected ({selectedIds.size})
                </button>
              )}
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Sort by:</label>
            <select
              value={currentSortValue}
              onChange={(e) => handleQuickSort(e.target.value)}
              className="text-sm bg-cyber-850 border border-cyber-700 text-white rounded px-2 py-1"
            >
              {sortOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Per page:</label>
            <select
              value={limit}
              onChange={(e) =>
                onFiltersChange({ ...filters, limit: parseInt(e.target.value), offset: 0 })
              }
              className="text-sm bg-cyber-850 border border-cyber-700 text-white rounded px-2 py-1"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-cyber-850 rounded-lg border border-cyber-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-cyber-700">
            <thead className="bg-cyber-900">
              <tr>
                {enableSelection && (
                  <th className="px-2 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-10">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === Math.min(6, detections.length) && selectedIds.size > 0}
                      onChange={() => selectedIds.size > 0 ? clearSelection() : selectAll()}
                      className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500"
                      title="Select all (max 6)"
                    />
                  </th>
                )}
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('title')}
                >
                  Title <SortIndicator field="title" />
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('source')}
                >
                  Source <SortIndicator field="source" />
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Language
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('severity')}
                >
                  Severity <SortIndicator field="severity" />
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  MITRE Tactics
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Techniques
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Log Sources
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('rule_created_date')}
                >
                  Created <SortIndicator field="rule_created_date" />
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('rule_modified_date')}
                >
                  Modified <SortIndicator field="rule_modified_date" />
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-cyan-400 transition-colors"
                  onClick={() => handleSort('status')}
                >
                  Status <SortIndicator field="status" />
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-700">
              {detections.map((detection) => (
                <tr
                  key={detection.id}
                  className={`hover:bg-cyber-800 cursor-pointer transition-colors ${
                    isSelected(detection.id) ? 'bg-cyan-500/10' : ''
                  }`}
                  onClick={() => window.location.href = `/detections/${detection.id}`}
                >
                  {enableSelection && (
                    <td className="px-2 py-3" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={isSelected(detection.id)}
                        onChange={() => {}}
                        onClick={(e) => toggleSelection(detection.id, e)}
                        disabled={!isSelected(detection.id) && !canSelect}
                        className="rounded bg-cyber-900 border-cyber-600 text-cyan-500 focus:ring-cyan-500 disabled:opacity-50"
                      />
                    </td>
                  )}
                  <td className="px-4 py-3 max-w-md">
                    <Link
                      to={`/detections/${detection.id}`}
                      className="text-sm font-medium text-cyan-400 hover:text-cyan-300 hover:underline"
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
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium border ${
                        sourceColors[detection.source] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                      }`}
                    >
                      {sourceLabels[detection.source] || detection.source}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="px-2 py-1 bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded text-xs font-medium uppercase">
                      {detection.language || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium border ${
                        severityColors[detection.severity]
                      }`}
                    >
                      {detection.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[220px]">
                      {detection.mitre_tactics.slice(0, 2).map((tactic) => (
                        <span
                          key={tactic}
                          className={`px-1.5 py-0.5 text-xs rounded border ${
                            tacticColors[tactic] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                          }`}
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
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[140px]">
                      {detection.mitre_techniques.slice(0, 2).map((tech) => (
                        <span
                          key={tech}
                          className="px-1.5 py-0.5 bg-cyber-700 text-gray-300 text-xs rounded"
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
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[160px]">
                      {detection.log_sources.slice(0, 2).map((source) => (
                        <span
                          key={source}
                          className="px-1.5 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs rounded"
                          title={source}
                        >
                          {source}
                        </span>
                      ))}
                      {detection.log_sources.length > 2 && (
                        <span
                          className="text-xs text-gray-500"
                          title={detection.log_sources.join(', ')}
                        >
                          +{detection.log_sources.length - 2}
                        </span>
                      )}
                      {detection.log_sources.length === 0 && (
                        <span className="text-xs text-gray-600">-</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className="text-xs text-gray-400"
                      title={formatDate(detection.rule_created_date)}
                    >
                      {formatRelativeDate(detection.rule_created_date)}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className="text-xs text-gray-400"
                      title={formatDate(detection.rule_modified_date)}
                    >
                      {formatRelativeDate(detection.rule_modified_date)}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium border ${
                        statusColors[detection.status]
                      }`}
                    >
                      {detection.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <div className="text-sm text-gray-400">
            Page {currentPage} of {totalPages}
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1 border border-cyber-700 rounded text-sm text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-cyber-800 hover:border-cyan-500/30 transition-colors"
            >
              Prev
            </button>
            {getVisiblePages().map((page, idx) => (
              typeof page === 'number' ? (
                <button
                  key={idx}
                  onClick={() => handlePageChange(page)}
                  className={`px-3 py-1 border rounded text-sm transition-colors ${
                    page === currentPage
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                      : 'border-cyber-700 text-gray-300 hover:bg-cyber-800 hover:border-cyan-500/30'
                  }`}
                >
                  {page}
                </button>
              ) : (
                <span key={idx} className="px-2 text-gray-500">
                  {page}
                </span>
              )
            ))}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1 border border-cyber-700 rounded text-sm text-gray-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-cyber-800 hover:border-cyan-500/30 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
