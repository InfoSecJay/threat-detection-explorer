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
    if (filters.offset) params.set('offset', String(filters.offset));
    if (filters.limit && filters.limit !== 50) params.set('limit', String(filters.limit));
    if (filters.sort_by && filters.sort_by !== 'title') params.set('sort_by', filters.sort_by);
    if (filters.sort_order && filters.sort_order !== 'asc') params.set('sort_order', filters.sort_order);

    setSearchParams(params);
  }, [filters, setSearchParams]);

  const { data, isLoading, error } = useDetections(filters);

  if (error) {
    return (
      <div className="bg-red-100 text-red-700 p-4 rounded-lg">
        Error loading detections: {error.message}
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Detection Rules</h1>
        <button
          onClick={() => setIsExportModalOpen(true)}
          className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
        >
          Export
        </button>
      </div>

      <div className="flex gap-6">
        {/* Filters sidebar */}
        <div className="w-64 flex-shrink-0">
          <FilterPanel filters={filters} onFiltersChange={setFilters} />
        </div>

        {/* Detection list */}
        <div className="flex-1">
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
