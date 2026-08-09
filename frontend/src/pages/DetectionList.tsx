import { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ActiveFilterPills } from '../components/ActiveFilterPills';
import { RuleList } from '../components/RuleList';
import { ExportModal } from '../components/ExportModal';
import { SearchBar } from '../components/SearchBar';
import { FilterSheet } from '../components/FilterSheet';
import { useDetections } from '../hooks/useDetections';
import type { SearchFilters } from '../types';
import { extractQueryParseError } from '../services/api';
import { countActiveFilters } from '../utils/filterUtils';
import { clipSm, clipMd } from '../constants/style';

/** Filter trigger — mirrors the SearchBar's height and clip so they read as a pair. */
function FilterButton({ activeCount, onClick }: { activeCount: number; onClick: () => void }) {
  const active = activeCount > 0;
  return (
    <button
      onClick={onClick}
      className={`shrink-0 flex items-center gap-2 px-3 py-2 text-xs font-display font-semibold uppercase tracking-wider border transition-colors ${
        active
          ? 'bg-matrix-500/10 text-matrix-400 border-matrix-500/40 hover:bg-matrix-500/20'
          : 'bg-void-900 text-gray-400 border-void-700 hover:text-white hover:border-void-600'
      }`}
      style={clipSm}
      aria-label={`Open filters${active ? ` (${activeCount} active)` : ''}`}
    >
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
      </svg>
      Filters
      {active && (
        <span className="ml-1 tabular-nums bg-matrix-500/25 text-matrix-300 px-1.5 py-0.5 text-[10px] rounded-sm">
          {activeCount}
        </span>
      )}
    </button>
  );
}

export function DetectionList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [selectedIdsForExport, setSelectedIdsForExport] = useState<string[]>([]);
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  // Pinned means the filter panel docks as a persistent side panel on
  // md+. Preference persists so users don't have to re-pin each visit.
  const [filterSheetPinned, setFilterSheetPinned] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('detection-list.filters.pinned') === '1';
  });
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(
      'detection-list.filters.pinned',
      filterSheetPinned ? '1' : '0',
    );
  }, [filterSheetPinned]);

  // Global keyboard shortcuts — `/` focuses the search bar (unless
  // typing elsewhere), Cmd/Ctrl+F opens the filter sheet. Escape
  // closes anything open (handled by the bar + sheet locally).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isTyping =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          (target as HTMLElement).isContentEditable);
      if (e.key === '/' && !isTyping) {
        e.preventDefault();
        const bar = document.querySelector<HTMLInputElement>(
          'input[aria-label="Search rules"]',
        );
        bar?.focus();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        setFilterSheetOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Parse filters from URL
  const parseFilters = (): SearchFilters => ({
    search: searchParams.get('search') || undefined,
    q: searchParams.get('q') || undefined,
    sources: searchParams.get('sources')?.split(',').filter(Boolean) || [],
    statuses: searchParams.get('statuses')?.split(',').filter(Boolean) || [],
    severities: searchParams.get('severities')?.split(',').filter(Boolean) || [],
    mitre_tactics: searchParams.get('mitre_tactics')?.split(',').filter(Boolean) || [],
    mitre_techniques: searchParams.get('mitre_techniques')?.split(',').filter(Boolean) || [],
    mitre_groups: searchParams.get('mitre_groups')?.split(',').filter(Boolean) || [],
    mitre_software: searchParams.get('mitre_software')?.split(',').filter(Boolean) || [],
    tags: searchParams.get('tags')?.split(',').filter(Boolean) || [],
    languages: searchParams.get('languages')?.split(',').filter(Boolean) || [],
    // Standardized taxonomy filters
    platforms: searchParams.get('platforms')?.split(',').filter(Boolean) || [],
    event_categories: searchParams.get('event_categories')?.split(',').filter(Boolean) || [],
    data_sources_normalized: searchParams.get('data_sources_normalized')?.split(',').filter(Boolean) || [],
    use_cases: searchParams.get('use_cases')?.split(',').filter(Boolean) || [],
    // Extracted observable filters
    event_ids: searchParams.get('event_ids')?.split(',').filter(Boolean) || [],
    process_names: searchParams.get('process_names')?.split(',').filter(Boolean) || [],
    query_complexity: searchParams.get('query_complexity')?.split(',').filter(Boolean) || [],
    api_actions: searchParams.get('api_actions')?.split(',').filter(Boolean) || [],
    file_paths: searchParams.get('file_paths')?.split(',').filter(Boolean) || [],
    registry_keys: searchParams.get('registry_keys')?.split(',').filter(Boolean) || [],
    network_indicators: searchParams.get('network_indicators')?.split(',').filter(Boolean) || [],
    target_resources: searchParams.get('target_resources')?.split(',').filter(Boolean) || [],
    source_tables: searchParams.get('source_tables')?.split(',').filter(Boolean) || [],
    offset: parseInt(searchParams.get('offset') || '0', 10),
    limit: parseInt(searchParams.get('limit') || '25', 10),
    sort_by: searchParams.get('sort_by') || 'title',
    sort_order: (searchParams.get('sort_order') as 'asc' | 'desc') || 'asc',
  });

  const [filters, setFilters] = useState<SearchFilters>(parseFilters);

  // Sync URL with filters
  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.q) params.set('q', filters.q);
    if (filters.sources?.length) params.set('sources', filters.sources.join(','));
    if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','));
    if (filters.severities?.length) params.set('severities', filters.severities.join(','));
    if (filters.mitre_tactics?.length) params.set('mitre_tactics', filters.mitre_tactics.join(','));
    if (filters.mitre_techniques?.length) params.set('mitre_techniques', filters.mitre_techniques.join(','));
    if (filters.mitre_groups?.length) params.set('mitre_groups', filters.mitre_groups.join(','));
    if (filters.mitre_software?.length) params.set('mitre_software', filters.mitre_software.join(','));
    if (filters.tags?.length) params.set('tags', filters.tags.join(','));
    if (filters.languages?.length) params.set('languages', filters.languages.join(','));
    // Standardized taxonomy filters
    if (filters.platforms?.length) params.set('platforms', filters.platforms.join(','));
    if (filters.event_categories?.length) params.set('event_categories', filters.event_categories.join(','));
    if (filters.data_sources_normalized?.length) params.set('data_sources_normalized', filters.data_sources_normalized.join(','));
    if (filters.use_cases?.length) params.set('use_cases', filters.use_cases.join(','));
    // Extracted observable filters
    if (filters.event_ids?.length) params.set('event_ids', filters.event_ids.join(','));
    if (filters.process_names?.length) params.set('process_names', filters.process_names.join(','));
    if (filters.query_complexity?.length) params.set('query_complexity', filters.query_complexity.join(','));
    if (filters.api_actions?.length) params.set('api_actions', filters.api_actions.join(','));
    if (filters.file_paths?.length) params.set('file_paths', filters.file_paths.join(','));
    if (filters.registry_keys?.length) params.set('registry_keys', filters.registry_keys.join(','));
    if (filters.network_indicators?.length) params.set('network_indicators', filters.network_indicators.join(','));
    if (filters.target_resources?.length) params.set('target_resources', filters.target_resources.join(','));
    if (filters.source_tables?.length) params.set('source_tables', filters.source_tables.join(','));
    if (filters.offset) params.set('offset', String(filters.offset));
    if (filters.limit && filters.limit !== 25) params.set('limit', String(filters.limit));
    if (filters.sort_by && filters.sort_by !== 'title') params.set('sort_by', filters.sort_by);
    if (filters.sort_order && filters.sort_order !== 'asc') params.set('sort_order', filters.sort_order);

    setSearchParams(params);
  }, [filters, setSearchParams]);

  const { data, isLoading, error } = useDetections(filters);

  // Query-parse errors (HTTP 400 from the backend) render inline
  // under the search bar; other errors get the full-page treatment.
  const queryError = useMemo(() => extractQueryParseError(error), [error]);
  const isQueryError = !!queryError;

  const handleQuerySubmit = (q: string) => {
    setFilters({ ...filters, q: q || undefined, offset: 0 });
  };

  const handleExportSelected = (ids: string[]) => {
    setSelectedIdsForExport(ids);
    setIsExportModalOpen(true);
  };

  if (error && !isQueryError) {
    return (
      <div className="bg-breach-500/10 text-breach-400 border border-breach-500/30 p-6"
        style={clipMd}
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
    <div className={filterSheetPinned ? 'md:pr-[400px] transition-[padding] duration-200' : 'transition-[padding] duration-200'}>
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
          style={clipSm}
        >
          <span className="flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export
          </span>
        </button>
      </div>

      {/* Search bar + Filter button. Lucene-syntax bar is the primary
          interface; sheet is the discoverable fallback for anyone who
          doesn't know the syntax. They compose (AND) at the API. */}
      <div className="mb-6 flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <SearchBar
            value={filters.q || ''}
            onSubmit={handleQuerySubmit}
            error={queryError}
          />
        </div>
        {/* Filter button hidden on md+ when the sheet is pinned —
            the panel is already visible so a "Filters" button would
            be redundant. Still shown on mobile since pinning is
            gated on md+. */}
        <div className={filterSheetPinned ? 'md:hidden' : ''}>
          <FilterButton
            activeCount={countActiveFilters(filters)}
            onClick={() => setFilterSheetOpen(true)}
          />
        </div>
      </div>

      <FilterSheet
        filters={filters}
        onFiltersChange={setFilters}
        open={filterSheetOpen}
        onClose={() => setFilterSheetOpen(false)}
        pinned={filterSheetPinned}
        onPinnedChange={(p) => {
          setFilterSheetPinned(p);
          // Unpinning while the modal is not deliberately open should
          // just dismiss the panel; pinning implies visibility.
          if (!p) setFilterSheetOpen(false);
        }}
      />

      {/* Results */}
      <div className="min-w-0">
        <ActiveFilterPills filters={filters} onFiltersChange={setFilters} />
        <RuleList
          detections={data?.items || []}
          total={data?.total || 0}
          filters={filters}
          onFiltersChange={setFilters}
          isLoading={isLoading}
          onExportSelected={handleExportSelected}
        />
      </div>

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => {
          setIsExportModalOpen(false);
          setSelectedIdsForExport([]);
        }}
        filters={filters}
        selectedIds={selectedIdsForExport.length > 0 ? selectedIdsForExport : undefined}
      />
    </div>
  );
}
