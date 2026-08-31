import { useRef, useState, useEffect, useMemo } from 'react';
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
import {
  mergeTokensIntoFilters,
  parseBar,
  reconcileFilterChange,
} from '../utils/querySync';
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
  // localStorage access throws (SecurityError) when site data is
  // blocked; a throw inside a useState initializer is a render-phase
  // crash, so both sides are guarded.
  const [filterSheetPinned, setFilterSheetPinned] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem('detection-list.filters.pinned') === '1';
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      window.localStorage.setItem(
        'detection-list.filters.pinned',
        filterSheetPinned ? '1' : '0',
      );
    } catch {
      /* preference simply does not persist */
    }
  }, [filterSheetPinned]);

  // Global keyboard shortcuts — `/` focuses the search bar and `f`
  // opens the filter sheet (both only when not typing in a field).
  // Escape closes anything open (handled by the bar + sheet locally).
  // `f` replaced Cmd/Ctrl+F (#49): intercepting that hijacked the
  // browser's find-in-page on the one page where people most want it.
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
      if (e.key === 'f' && !isTyping && !e.metaKey && !e.ctrlKey && !e.altKey) {
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
    building_block:
      searchParams.get('building_block') === 'true'
        ? true
        : searchParams.get('building_block') === 'false'
          ? false
          : undefined,
    min_quality: (() => {
      const raw = searchParams.get('min_quality');
      const n = raw === null ? NaN : parseInt(raw, 10);
      return Number.isFinite(n) && n >= 0 && n <= 100 ? n : undefined;
    })(),
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
    sort_by: searchParams.get('sort_by') || 'relevance',
    sort_order: (searchParams.get('sort_order') as 'asc' | 'desc') || 'desc',
  });

  const [filters, setFilters] = useState<SearchFilters>(parseFilters);

  // Serialize filters to the canonical URL form (defaults omitted).
  const buildParams = (f: SearchFilters): URLSearchParams => {
    const params = new URLSearchParams();
    const filters = f;
    if (filters.search) params.set('search', filters.search);
    if (filters.q) params.set('q', filters.q);
    if (filters.sources?.length) params.set('sources', filters.sources.join(','));
    if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','));
    if (filters.building_block !== undefined) params.set('building_block', String(filters.building_block));
    if (filters.min_quality !== undefined) params.set('min_quality', String(filters.min_quality));
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
    if (filters.sort_by && filters.sort_by !== 'relevance') params.set('sort_by', filters.sort_by);
    if (filters.sort_order && filters.sort_order !== 'desc') params.set('sort_order', filters.sort_order);
    return params;
  };

  // Two-way URL sync. Filters -> URL pushes a history entry (so Back
  // steps through filter states); URL -> filters re-derives state when
  // the URL changes underneath us (Back/Forward, a link into the page
  // with different params). Each direction is guarded by string
  // equality, which is what breaks the loop -- and what previously
  // made Back "snap forward": the one-way effect re-pushed the stale
  // in-memory filters on every popstate.
  const initialSyncDone = useRef(false);
  useEffect(() => {
    const params = buildParams(filters);
    if (params.toString() === searchParams.toString()) return;
    // The first run only normalizes whatever the URL had (ordering,
    // defaults); replace so it does not become a history entry.
    setSearchParams(params, { replace: !initialSyncDone.current });
    initialSyncDone.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps -- searchParams is read, not a trigger
  }, [filters, setSearchParams]);

  useEffect(() => {
    const fromUrl = parseFilters();
    if (buildParams(fromUrl).toString() !== buildParams(filters).toString()) {
      setFilters(fromUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the URL should trigger this direction
  }, [searchParams]);

  const { data, isLoading, error } = useDetections(filters);

  // Query-parse errors (HTTP 400 from the backend) render inline
  // under the search bar; other errors get the full-page treatment.
  const queryError = useMemo(() => extractQueryParseError(error), [error]);
  const isQueryError = !!queryError;

  const handleQuerySubmit = (q: string) => {
    setFilters({ ...filters, q: q || undefined, offset: 0 });
  };

  // Bar <-> sheet translation (#13): the sheet and pills render a VIEW
  // with the bar's flat `field:value` tokens merged into the array
  // facets; edits made against that view reconcile back onto whichever
  // surface owns each value (bar token vs array filter).
  const parsedBar = useMemo(() => parseBar(filters.q || ''), [filters.q]);
  const viewFilters = useMemo(
    () => mergeTokensIntoFilters(filters, parsedBar),
    [filters, parsedBar],
  );
  const handleViewFiltersChange = (next: SearchFilters) => {
    setFilters(reconcileFilterChange(filters, viewFilters, next, parsedBar));
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
            activeCount={countActiveFilters(viewFilters)}
            onClick={() => setFilterSheetOpen(true)}
          />
        </div>
      </div>

      <FilterSheet
        filters={viewFilters}
        onFiltersChange={handleViewFiltersChange}
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
        <ActiveFilterPills filters={viewFilters} onFiltersChange={handleViewFiltersChange} />
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
