import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { FilterPanel } from '../components/FilterPanel';
import { RuleList } from '../components/RuleList';
import { ExportModal } from '../components/ExportModal';
import { useDetections } from '../hooks/useDetections';
import type { SearchFilters } from '../types';

export function DetectionList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [searchInput, setSearchInput] = useState(searchParams.get('search') || '');

  // Parse filters from URL
  const parseFilters = (): SearchFilters => ({
    search: searchParams.get('search') || undefined,
    sources: searchParams.get('sources')?.split(',').filter(Boolean) || [],
    statuses: searchParams.get('statuses')?.split(',').filter(Boolean) || [],
    severities: searchParams.get('severities')?.split(',').filter(Boolean) || [],
    mitre_tactics: searchParams.get('mitre_tactics')?.split(',').filter(Boolean) || [],
    mitre_techniques: searchParams.get('mitre_techniques')?.split(',').filter(Boolean) || [],
    tags: searchParams.get('tags')?.split(',').filter(Boolean) || [],
    log_sources: searchParams.get('log_sources')?.split(',').filter(Boolean) || [],
    languages: searchParams.get('languages')?.split(',').filter(Boolean) || [],
    // Standardized taxonomy filters
    platforms: searchParams.get('platforms')?.split(',').filter(Boolean) || [],
    event_categories: searchParams.get('event_categories')?.split(',').filter(Boolean) || [],
    data_sources_normalized: searchParams.get('data_sources_normalized')?.split(',').filter(Boolean) || [],
    offset: parseInt(searchParams.get('offset') || '0', 10),
    limit: parseInt(searchParams.get('limit') || '50', 10),
    sort_by: searchParams.get('sort_by') || 'title',
    sort_order: (searchParams.get('sort_order') as 'asc' | 'desc') || 'asc',
  });

  const [filters, setFilters] = useState<SearchFilters>(parseFilters);

  // Sync URL with filters
  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.sources?.length) params.set('sources', filters.sources.join(','));
    if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','));
    if (filters.severities?.length) params.set('severities', filters.severities.join(','));
    if (filters.mitre_tactics?.length) params.set('mitre_tactics', filters.mitre_tactics.join(','));
    if (filters.mitre_techniques?.length) params.set('mitre_techniques', filters.mitre_techniques.join(','));
    if (filters.tags?.length) params.set('tags', filters.tags.join(','));
    if (filters.log_sources?.length) params.set('log_sources', filters.log_sources.join(','));
    if (filters.languages?.length) params.set('languages', filters.languages.join(','));
    // Standardized taxonomy filters
    if (filters.platforms?.length) params.set('platforms', filters.platforms.join(','));
    if (filters.event_categories?.length) params.set('event_categories', filters.event_categories.join(','));
    if (filters.data_sources_normalized?.length) params.set('data_sources_normalized', filters.data_sources_normalized.join(','));
    if (filters.offset) params.set('offset', String(filters.offset));
    if (filters.limit && filters.limit !== 50) params.set('limit', String(filters.limit));
    if (filters.sort_by && filters.sort_by !== 'title') params.set('sort_by', filters.sort_by);
    if (filters.sort_order && filters.sort_order !== 'asc') params.set('sort_order', filters.sort_order);

    setSearchParams(params);
  }, [filters, setSearchParams]);

  const { data, isLoading, error } = useDetections(filters);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFilters({ ...filters, search: searchInput || undefined, offset: 0 });
  };

  const handleClearSearch = () => {
    setSearchInput('');
    setFilters({ ...filters, search: undefined, offset: 0 });
  };

  if (error) {
    return (
      <div className="bg-breach-500/10 text-breach-400 border border-breach-500/30 p-6"
        style={{
          clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
        }}
      >
        <div className="flex items-center gap-3">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span className="font-mono text-sm">ERROR: {error.message}</span>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Page Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-display font-bold text-white tracking-wider uppercase">
            Detection Rules
          </h1>
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-void-800 border border-void-600">
            <span className="w-2 h-2 bg-matrix-500 rounded-full animate-pulse" />
            <span className="text-xs font-mono text-gray-400">
              {data?.total.toLocaleString() || '...'} <span className="text-gray-500">RULES</span>
            </span>
          </div>
        </div>
        <button
          onClick={() => setIsExportModalOpen(true)}
          className="px-4 py-2 bg-pulse-500 text-void-950 font-display font-semibold text-sm uppercase tracking-wider hover:bg-pulse-400 transition-colors"
          style={{
            clipPath: 'polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px))',
          }}
        >
          <span className="flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export
          </span>
        </button>
      </div>

      {/* Search Bar */}
      <form onSubmit={handleSearchSubmit} className="mb-6">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by title, description, detection logic, author..."
              className="w-full pl-12 pr-10 py-3 bg-void-850 border border-void-700 text-white placeholder-gray-500 focus:ring-2 focus:ring-matrix-500/50 focus:border-matrix-500/50 transition-all"
              style={{
                clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px))',
              }}
            />
            {searchInput && (
              <button
                type="button"
                onClick={handleClearSearch}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-matrix-500 transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
          <button
            type="submit"
            className="btn-primary px-8"
          >
            Search
          </button>
        </div>
        {filters.search && (
          <p className="mt-3 text-sm font-mono text-gray-500">
            <span className="text-gray-600">[</span>
            QUERY
            <span className="text-gray-600">]</span>
            {' '}<span className="text-matrix-500">"{filters.search}"</span>
          </p>
        )}
      </form>

      {/* Main Content Area */}
      <div className="flex gap-6">
        {/* Filters Sidebar */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel filters={filters} onFiltersChange={setFilters} />
        </div>

        {/* Detection List */}
        <div className="flex-1 min-w-0">
          <RuleList
            detections={data?.items || []}
            total={data?.total || 0}
            filters={filters}
            onFiltersChange={setFilters}
            isLoading={isLoading}
          />
        </div>
      </div>

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        filters={filters}
      />
    </div>
  );
}
