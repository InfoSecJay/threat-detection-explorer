import { Link } from 'react-router-dom';
import type { Detection, SearchFilters } from '../types';
import { useMitre } from '../contexts/MitreContext';

interface RuleListProps {
  detections: Detection[];
  total: number;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  isLoading?: boolean;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
  unknown: 'bg-gray-100 text-gray-800',
};

const sourceColors: Record<string, string> = {
  sigma: 'bg-purple-100 text-purple-800',
  elastic: 'bg-blue-100 text-blue-800',
  splunk: 'bg-orange-100 text-orange-800',
  sublime: 'bg-pink-100 text-pink-800',
  elastic_protections: 'bg-cyan-100 text-cyan-800',
  lolrmm: 'bg-green-100 text-green-800',
};

const statusColors: Record<string, string> = {
  stable: 'bg-green-100 text-green-800',
  experimental: 'bg-yellow-100 text-yellow-800',
  deprecated: 'bg-red-100 text-red-800',
  unknown: 'bg-gray-100 text-gray-800',
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
  TA0001: 'bg-red-50 text-red-700 border-red-200',
  TA0002: 'bg-orange-50 text-orange-700 border-orange-200',
  TA0003: 'bg-amber-50 text-amber-700 border-amber-200',
  TA0004: 'bg-yellow-50 text-yellow-700 border-yellow-200',
  TA0005: 'bg-lime-50 text-lime-700 border-lime-200',
  TA0006: 'bg-green-50 text-green-700 border-green-200',
  TA0007: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  TA0008: 'bg-teal-50 text-teal-700 border-teal-200',
  TA0009: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  TA0010: 'bg-sky-50 text-sky-700 border-sky-200',
  TA0011: 'bg-blue-50 text-blue-700 border-blue-200',
  TA0040: 'bg-violet-50 text-violet-700 border-violet-200',
  TA0042: 'bg-purple-50 text-purple-700 border-purple-200',
  TA0043: 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200',
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
}: RuleListProps) {
  const { getTacticName, getTechniqueName } = useMitre();
  const limit = filters.limit || 50;
  const offset = filters.offset || 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit);

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
      <span className="ml-1">
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
        <div className="animate-spin h-8 w-8 border-4 border-blue-600 border-t-transparent rounded-full mx-auto"></div>
        <p className="mt-2 text-gray-600">Loading detections...</p>
      </div>
    );
  }

  if (detections.length === 0) {
    return (
      <div className="text-center py-8 bg-white rounded-lg shadow">
        <p className="text-gray-600">No detections found.</p>
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
        <p className="text-sm text-gray-600">
          Showing {offset + 1}-{Math.min(offset + limit, total)} of{' '}
          {total.toLocaleString()} detections
        </p>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Sort by:</label>
            <select
              value={currentSortValue}
              onChange={(e) => handleQuickSort(e.target.value)}
              className="text-sm border border-gray-300 rounded px-2 py-1 bg-white"
            >
              {sortOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-600">Per page:</label>
            <select
              value={limit}
              onChange={(e) =>
                onFiltersChange({ ...filters, limit: parseInt(e.target.value), offset: 0 })
              }
              className="text-sm border border-gray-300 rounded px-2 py-1 bg-white"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => handleSort('title')}
                >
                  Title <SortIndicator field="title" />
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => handleSort('source')}
                >
                  Source <SortIndicator field="source" />
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Language
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => handleSort('severity')}
                >
                  Severity <SortIndicator field="severity" />
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  MITRE Tactics
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Techniques
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => handleSort('rule_modified_date')}
                >
                  Modified <SortIndicator field="rule_modified_date" />
                </th>
                <th
                  className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => handleSort('status')}
                >
                  Status <SortIndicator field="status" />
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {detections.map((detection) => (
                <tr
                  key={detection.id}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => window.location.href = `/detections/${detection.id}`}
                >
                  <td className="px-4 py-3 max-w-md">
                    <Link
                      to={`/detections/${detection.id}`}
                      className="text-sm font-medium text-blue-600 hover:text-blue-800 hover:underline"
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
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        sourceColors[detection.source] || 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {sourceLabels[detection.source] || detection.source}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="px-2 py-1 bg-indigo-50 text-indigo-700 rounded text-xs font-medium uppercase">
                      {detection.language || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
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
                            tacticColors[tactic] || 'bg-gray-50 text-gray-700 border-gray-200'
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
                        <span className="text-xs text-gray-400">-</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[140px]">
                      {detection.mitre_techniques.slice(0, 2).map((tech) => (
                        <span
                          key={tech}
                          className="px-1.5 py-0.5 bg-gray-100 text-gray-700 text-xs rounded"
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
                        <span className="text-xs text-gray-400">-</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className="text-xs text-gray-600"
                      title={formatDate(detection.rule_modified_date)}
                    >
                      {formatRelativeDate(detection.rule_modified_date)}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
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
          <div className="text-sm text-gray-600">
            Page {currentPage} of {totalPages}
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1 border rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
            >
              ← Prev
            </button>
            {getVisiblePages().map((page, idx) => (
              typeof page === 'number' ? (
                <button
                  key={idx}
                  onClick={() => handlePageChange(page)}
                  className={`px-3 py-1 border rounded text-sm ${
                    page === currentPage
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'hover:bg-gray-50'
                  }`}
                >
                  {page}
                </button>
              ) : (
                <span key={idx} className="px-2 text-gray-400">
                  {page}
                </span>
              )
            ))}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1 border rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
