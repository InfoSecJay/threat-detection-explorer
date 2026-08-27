import axios from 'axios';
import type {
  Detection,
  DetectionListResponse,
  Repository,
  SyncResponse,
  IngestionResponse,
  SearchFilters,
  CompareResponse,
  SideBySideResponse,
  Statistics,
  ExportRequest,
} from '../types';

// API base URL - uses environment variable in production, or relative path for local dev
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Repository endpoints
export const repositoriesApi = {
  list: async (): Promise<Repository[]> => {
    const response = await api.get('/repositories');
    return response.data;
  },

  get: async (name: string): Promise<Repository> => {
    const response = await api.get(`/repositories/${name}`);
    return response.data;
  },

  sync: async (name: string): Promise<SyncResponse> => {
    const response = await api.post(`/repositories/${name}/sync`);
    return response.data;
  },

  syncAll: async (): Promise<SyncResponse[]> => {
    const response = await api.post('/repositories/sync-all');
    return response.data;
  },

  ingest: async (name: string): Promise<IngestionResponse> => {
    const response = await api.post(`/repositories/${name}/ingest`);
    return response.data;
  },

  ingestAll: async (): Promise<IngestionResponse[]> => {
    const response = await api.post('/repositories/ingest-all');
    return response.data;
  },
};

/** Serialize SearchFilters to URL params — shared by list() and
 * getFacets() so both hit the API with identical filter semantics. */
function buildFilterParams(filters: SearchFilters, includePagination = true): URLSearchParams {
  const params = new URLSearchParams();

  if (filters.search) params.set('search', filters.search);
  if (filters.q) params.set('q', filters.q);
  if (filters.sources?.length) params.set('sources', filters.sources.join(','));
  if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','));
  if (filters.severities?.length) params.set('severities', filters.severities.join(','));
  if (filters.languages?.length) params.set('languages', filters.languages.join(','));
  if (filters.mitre_tactics?.length) params.set('mitre_tactics', filters.mitre_tactics.join(','));
  if (filters.mitre_techniques?.length) params.set('mitre_techniques', filters.mitre_techniques.join(','));
  if (filters.mitre_groups?.length) params.set('mitre_groups', filters.mitre_groups.join(','));
  if (filters.mitre_software?.length) params.set('mitre_software', filters.mitre_software.join(','));
  if (filters.tags?.length) params.set('tags', filters.tags.join(','));
  // Canonical taxonomy filters
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

  if (includePagination) {
    if (filters.offset !== undefined) params.set('offset', String(filters.offset));
    if (filters.limit !== undefined) params.set('limit', String(filters.limit));
    if (filters.sort_by) params.set('sort_by', filters.sort_by);
    if (filters.sort_order) params.set('sort_order', filters.sort_order);
  }

  return params;
}

export type FacetOption = { value: string; count: number };

/** Per-dimension facet counts from /detections/facets, scoped to the
 * active query (each dimension excludes its own selection). */
export interface DetectionFacets {
  sources: FacetOption[];
  severities: FacetOption[];
  languages: FacetOption[];
  mitre_tactics: FacetOption[];
  mitre_techniques: FacetOption[];
  platforms: FacetOption[];
  data_sources: FacetOption[];
  event_types: FacetOption[];
}

// Detection endpoints
export const detectionsApi = {
  list: async (filters: SearchFilters = {}): Promise<DetectionListResponse> => {
    const params = buildFilterParams(filters);
    const response = await api.get(`/detections?${params.toString()}`);
    return response.data;
  },

  getFacets: async (filters: SearchFilters = {}): Promise<DetectionFacets> => {
    const params = buildFilterParams(filters, false);
    const response = await api.get(`/detections/facets?${params.toString()}`);
    return response.data;
  },

  search: async (filters: SearchFilters): Promise<DetectionListResponse> => {
    const response = await api.post('/detections/search', filters);
    return response.data;
  },

  get: async (id: string): Promise<Detection> => {
    const response = await api.get(`/detections/${id}`);
    return response.data;
  },

  getStatistics: async (): Promise<Statistics> => {
    const response = await api.get('/detections/statistics');
    return response.data;
  },

  getFilterOptions: async (): Promise<{
    sources: string[];
    statuses: string[];
    severities: string[];
    languages: string[];
    platforms: Array<{ value: string; count: number }>;
    data_sources: Array<{ value: string; count: number }>;
    event_types: Array<{ value: string; count: number }>;
    use_cases?: Array<{ value: string; count: number }>;
    mitre_groups?: Array<{ value: string; count: number }>;
    mitre_software?: Array<{ value: string; count: number }>;
  }> => {
    const response = await api.get('/detections/filters');
    return response.data;
  },
};

// Compare endpoints
export const compareApi = {
  compare: async (params: {
    technique?: string;
    keyword?: string;
    platform?: string;
    sources?: string[];
  }): Promise<CompareResponse> => {
    const searchParams = new URLSearchParams();
    if (params.technique) searchParams.set('technique', params.technique);
    if (params.keyword) searchParams.set('keyword', params.keyword);
    if (params.platform) searchParams.set('platform', params.platform);
    if (params.sources?.length) searchParams.set('sources', params.sources.join(','));

    const response = await api.get(`/compare?${searchParams.toString()}`);
    return response.data;
  },

  coverageGap: async (baseSource: string, compareSource: string): Promise<{
    base_source: string;
    compare_source: string;
    base_technique_count: number;
    compare_technique_count: number;
    overlap_count: number;
    gaps: string[];
    unique_to_compare: string[];
  }> => {
    const response = await api.get(`/compare/coverage-gap?base_source=${baseSource}&compare_source=${compareSource}`);
    return response.data;
  },

  sideBySide: async (ids: string[]): Promise<SideBySideResponse> => {
    const response = await api.post('/compare/side-by-side', { ids });
    return response.data;
  },

  coverageMatrix: async (params?: {
    tactic?: string;
    include_subtechniques?: boolean;
  }): Promise<CoverageMatrixResponse> => {
    const searchParams = new URLSearchParams();
    if (params?.tactic) searchParams.set('tactic', params.tactic);
    if (params?.include_subtechniques !== undefined) {
      searchParams.set('include_subtechniques', String(params.include_subtechniques));
    }
    const response = await api.get(`/compare/coverage-matrix?${searchParams.toString()}`);
    return response.data;
  },
};

// Export endpoints
export const exportApi = {
  export: async (request: ExportRequest): Promise<Blob> => {
    const response = await api.post('/export', request, {
      responseType: 'blob',
    });
    return response.data;
  },
};

// Coverage Matrix types
export interface TechniqueCoverage {
  id: string;
  name: string;
  is_subtechnique: boolean;
  coverage: Record<string, number>;
  total_detections: number;
  sources_with_coverage: number;
}

export interface TacticCoverage {
  id: string;
  name: string;
  short_name: string;
  techniques: TechniqueCoverage[];
  technique_count: number;
}

export interface CoverageMatrixResponse {
  sources: string[];
  tactics: TacticCoverage[];
  summary: {
    total_tactics: number;
    total_techniques: number;
    techniques_with_any_coverage: number;
    overall_coverage_percent: number;
    source_coverage: Record<string, {
      covered_techniques: number;
      total_techniques: number;
      coverage_percent: number;
    }>;
  };
}

// MITRE ATT&CK types
export interface MitreTactic {
  id: string;
  name: string;
  short_name: string;
  url: string;
  deprecated: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  url: string;
  deprecated: boolean;
  is_subtechnique: boolean;
  // Enriched metadata (populated by backend v1.4+). Optional because
  // older cached payloads may predate the enrichment.
  description?: string;
  platforms?: string[];
  data_sources?: string[];
  detection?: string;
  parent_id?: string | null;
  version?: string | null;
}

export interface MitreData {
  tactics: Record<string, MitreTactic>;
  techniques: Record<string, MitreTechnique>;
  stats: {
    tactics_count: number;
    techniques_count: number;
    subtechniques_count: number;
    last_fetch: string | null;
    loaded: boolean;
  };
}

// MITRE ATT&CK endpoints
export const mitreApi = {
  getData: async (): Promise<MitreData> => {
    const response = await api.get('/mitre');
    return response.data;
  },

  getTactics: async (): Promise<Record<string, MitreTactic>> => {
    const response = await api.get('/mitre/tactics');
    return response.data;
  },

  getTechniques: async (): Promise<Record<string, MitreTechnique>> => {
    const response = await api.get('/mitre/techniques');
    return response.data;
  },

  refresh: async (): Promise<{ success: boolean; stats: MitreData['stats'] }> => {
    const response = await api.post('/mitre/refresh');
    return response.data;
  },
};

// Release types
export interface ReleaseSource {
  id: string;
  name: string;
  owner: string;
  repo: string;
}

export interface Release {
  id: number;
  tag_name: string;
  name: string;
  published_at: string;
  html_url: string;
  body: string;
  author: string | null;
}

// Releases endpoints
export const releasesApi = {
  listSources: async (): Promise<ReleaseSource[]> => {
    const response = await api.get('/releases');
    return response.data;
  },

  getReleases: async (source: string, perPage: number = 5): Promise<Release[]> => {
    const response = await api.get(`/releases/${source}?per_page=${perPage}`);
    return response.data;
  },
};

// Trending types
export interface TrendingTechnique {
  technique_id: string;
  count: number;
  sources: string[];
  latest_date: string | null;
}

export interface TrendingPlatform {
  platform: string;
  count: number;
  sources: string[];
  latest_date: string | null;
}

export interface TrendingTechniquesResponse {
  period_days: number;
  cutoff_date: string;
  techniques: TrendingTechnique[];
}

export interface TrendingPlatformsResponse {
  period_days: number;
  cutoff_date: string;
  platforms: TrendingPlatform[];
}

export interface TrendingSummaryResponse {
  period_days: number;
  cutoff_date: string;
  total_created: number;
  total_modified: number;
  // {source: {created, modified}} — zero-activity sources omitted.
  by_source: Record<string, { created: number; modified: number }>;
}

export interface TrendingUseCase {
  use_case: string;
  count: number;
  sources: string[];
  latest_date: string | null;
}

export interface TrendingUseCasesResponse {
  period_days: number;
  cutoff_date: string;
  use_cases: TrendingUseCase[];
}

// Actors listing — full MITRE catalog with our coverage overlaid.
// Powers /actors page.
export interface ActorListGroup {
  id: string;
  name: string;
  aliases: string[];
  description: string;         // truncated snippet
  deprecated: boolean;
  modified: string | null;     // ATT&CK last-modified timestamp
  technique_count: number;         // known techniques from MITRE
  covered_technique_count: number; // raw: how many have any rules (detail-page metric)
  our_rule_count: number;          // DEDICATED rules: ID-tagged, story-labeled, or name-in-title
  mention_count: number;           // REFERENCED rules: named in prose/refs only, minus dedicated
  sources_with_coverage: string[];
  weighted_coverage: number | null; // distinctiveness-weighted, 0..1
  gap_count: number;                // techniques with no rules
  weighted_gap: number;             // uncovered weight mass — primary rank key
  // MISP-galaxy enrichment (Phase 1) — every field nullable; roughly a
  // third of actors have partial or no galaxy match.
  origin_country?: string | null;   // ISO-2
  motivations?: string[];
  target_sectors?: string[];
  target_regions?: string[];
}

export interface ActorListSoftware {
  id: string;
  name: string;
  type: 'malware' | 'tool' | 'unknown';
  aliases: string[];
  description: string;
  deprecated: boolean;
  modified: string | null;
  weighted_coverage: number | null;
  gap_count: number;
  weighted_gap: number;
  platforms: string[];
  // Distinct actors with a `uses` relationship — the software tab's
  // primary stat and default sort.
  used_by_actor_count: number;
  used_by_actors: string[];
  technique_count: number;
  covered_technique_count: number;
  our_rule_count: number;
  mention_count: number;
  sources_with_coverage: string[];
}

export interface ActorsListResponse {
  groups: ActorListGroup[];
  software: ActorListSoftware[];
  total_groups: number;
  total_software: number;
  groups_with_coverage: number;
  software_with_coverage: number;
}

export type ActorMatchMode = 'exact' | 'coverage' | 'mention';

// Filtered /actors mode (Phase 4): same endpoint, any query param
// switches the response to items + facets.
export interface ActorsQueryParams {
  kind: 'groups' | 'software';
  sector?: string[];
  region?: string[];
  motivation?: string[];
  origin?: string[];
  type?: string[];          // software only
  used_by_actor?: string;   // software only: G-ID
  min_gaps?: number;
  has_exact_rules?: boolean;
  q?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}

// A query item is a group entry; software rows additionally carry
// type/platforms/used-by and lack the galaxy context fields.
export type ActorsQueryItem = ActorListGroup &
  Partial<Pick<ActorListSoftware, 'type' | 'platforms' | 'used_by_actor_count' | 'used_by_actors'>>;

export interface ActorsQueryResponse {
  items: ActorsQueryItem[];
  total: number;
  page: number;
  per_page: number;
  // Groups: sector/region/motivation/origin. Software: type.
  facets: Partial<Record<'sector' | 'region' | 'motivation' | 'origin' | 'type', Record<string, number>>>;
  summary: {
    total_groups: number;
    total_software: number;
    groups_with_coverage: number;
    software_with_coverage: number;
  };
}

export interface ActorTechniqueEntry {
  technique_id: string;
  technique_name: string;
  has_rules: boolean;
  rule_count: number;
  // Distinctiveness weight log(N/n_t); null when no actor uses the
  // technique (excluded from the weight corpus).
  weight: number | null;
}

export interface ActorAssociatedSoftware {
  id: string;
  name: string;
  type: 'malware' | 'tool' | 'unknown';
  has_rules: boolean;
  rule_count: number;
}

export interface ActorAssociatedGroup {
  id: string;
  name: string;
  aliases: string[];
  has_rules: boolean;
  rule_count: number;
}

export interface ActorReference {
  source_name: string;
  url: string;
  description: string;
}

export interface ActorMatchCounts {
  exact: number;
  coverage: number;
  mention: number;
}

// Why a rule counted under the selected match mode (issue #34).
// Dedicated: id-tag / story / title. Referenced: description / tag /
// use-case / reference. Empty in coverage mode.
export type ActorMatchReason =
  | 'id-tag' | 'story' | 'title'
  | 'description' | 'tag' | 'use-case' | 'reference';

export interface ActorDetailRule {
  id: string;
  rule_id: string | null;
  title: string;
  source: string;
  severity: string;
  language: string;
  techniques: string[];
  platforms: string[];
  date: string | null;
  match_reasons: ActorMatchReason[];
}

export interface ActorDetail {
  id: string;
  kind: 'group' | 'software';
  name: string;
  description: string;
  mitre_url: string;
  references: ActorReference[];
  deprecated: boolean;
  aliases: string[];
  // Present only for software.
  type?: 'malware' | 'tool' | 'unknown';
  platforms?: string[];

  // MISP-galaxy context (groups; null/empty when no galaxy match).
  origin_country?: string | null;
  motivations?: string[];
  target_sectors?: string[];
  target_regions?: string[];
  target_countries?: string[];

  technique_count: number;
  covered_technique_count: number;
  // Distinctiveness-weighted scores (Phase 2 scoring rework).
  weighted_coverage: number | null;
  gap_count: number;
  weighted_gap: number;
  techniques: ActorTechniqueEntry[];

  // Cross-references (one or the other depending on kind).
  associated_software?: ActorAssociatedSoftware[];
  associated_groups?: ActorAssociatedGroup[];

  match_counts: ActorMatchCounts;
  match_mode: ActorMatchMode;
  rules: ActorDetailRule[];
}

// Query language field registry — hydrated from backend/app/services/
// query_parser.py so the docs page stays in sync automatically.
export interface QueryFieldSpec {
  aliases: string[];
  kind: string;
  columns: string[];
  description: string;
  examples: string[];
}

export interface QueryFieldsResponse {
  fields: QueryFieldSpec[];
}

export const queryApi = {
  getFields: async (): Promise<QueryFieldsResponse> => {
    const response = await api.get('/query/fields');
    return response.data;
  },
};

// Parse a backend query-parse error response into a normalized shape
// the SearchBar can render inline. Backend returns 400 with detail =
// {error, message, position, suggestion}.
export interface QueryParseErrorDetail {
  error: string;
  message: string;
  position: number | null;
  suggestion: string | null;
}

export function extractQueryParseError(err: unknown): QueryParseErrorDetail | null {
  // axios error shape
  const anyErr = err as { response?: { status?: number; data?: { detail?: unknown } } };
  if (!anyErr?.response || anyErr.response.status !== 400) return null;
  const detail = anyErr.response.data?.detail;
  if (detail && typeof detail === 'object' && 'error' in detail && (detail as { error: string }).error === 'query_parse_error') {
    return detail as QueryParseErrorDetail;
  }
  return null;
}

/** Save a blob as a file, preferring the server's filename. */
function triggerDownload(blob: Blob, contentDisposition: string | undefined, fallback: string) {
  const match = contentDisposition?.match(/filename="?([^";]+)"?/);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = match?.[1] ?? fallback;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const actorsApi = {
  list: async (): Promise<ActorsListResponse> => {
    const response = await api.get('/actors');
    return response.data;
  },
  query: async (params: ActorsQueryParams): Promise<ActorsQueryResponse> => {
    const search = new URLSearchParams();
    search.set('kind', params.kind);
    for (const dim of ['sector', 'region', 'motivation', 'origin', 'type'] as const) {
      for (const v of params[dim] ?? []) search.append(dim, v);
    }
    if (params.used_by_actor) search.set('used_by_actor', params.used_by_actor);
    if (params.min_gaps !== undefined) search.set('min_gaps', String(params.min_gaps));
    if (params.has_exact_rules !== undefined) search.set('has_exact_rules', String(params.has_exact_rules));
    if (params.q) search.set('q', params.q);
    if (params.sort) search.set('sort', params.sort);
    if (params.order) search.set('order', params.order);
    if (params.page) search.set('page', String(params.page));
    if (params.per_page) search.set('per_page', String(params.per_page));
    const response = await api.get(`/actors?${search.toString()}`);
    return response.data;
  },
  /** Download an ATT&CK Navigator layer for one actor / software. */
  downloadNavigatorLayer: async (
    actorId: string,
    matchMode: ActorMatchMode = 'coverage',
  ): Promise<void> => {
    const response = await api.get(
      `/actors/${actorId}/navigator-layer?match_mode=${matchMode}`,
      { responseType: 'blob' },
    );
    triggerDownload(response.data, response.headers['content-disposition'],
      `${actorId.toLowerCase()}-navigator-layer.json`);
  },
  /** Download a combined Navigator layer for the current filter set. */
  downloadBulkNavigatorLayer: async (
    params: Omit<ActorsQueryParams, 'kind' | 'sort' | 'order' | 'page' | 'per_page'>,
  ): Promise<void> => {
    const search = new URLSearchParams();
    for (const dim of ['sector', 'region', 'motivation', 'origin'] as const) {
      for (const v of params[dim] ?? []) search.append(dim, v);
    }
    if (params.min_gaps !== undefined) search.set('min_gaps', String(params.min_gaps));
    if (params.has_exact_rules !== undefined) search.set('has_exact_rules', String(params.has_exact_rules));
    if (params.q) search.set('q', params.q);
    const response = await api.get(`/actors/navigator-layer?${search.toString()}`, {
      responseType: 'blob',
    });
    triggerDownload(response.data, response.headers['content-disposition'],
      'detection-coverage-actors.json');
  },
  get: async (
    actorId: string,
    matchMode: ActorMatchMode = 'exact',
  ): Promise<ActorDetail> => {
    const response = await api.get(
      `/actors/${actorId}?match_mode=${matchMode}`,
    );
    return response.data;
  },
};

export interface WeeklyActivityResponse {
  weeks: number;
  // Week-start ISO dates (Monday), oldest → newest.
  week_starts: string[];
  // {source: [count_per_week…]} — same order as week_starts. Sources
  // with zero activity in the window are omitted.
  by_source: Record<string, number[]>;
}

// Activity filters — shared by trending + recent-rules. Optional
// comma-separated narrowing so the Intel page can answer questions like
// "top techniques in new O365 rules" or "new Splunk rules this month".
export interface ActivityFilters {
  sources?: string[];
  platforms?: string[];
  event_types?: string[];
}

function activityFilterParams(filters: ActivityFilters): string {
  const parts: string[] = [];
  if (filters.sources?.length) parts.push(`sources=${filters.sources.join(',')}`);
  if (filters.platforms?.length) parts.push(`platforms=${filters.platforms.join(',')}`);
  if (filters.event_types?.length) parts.push(`event_types=${filters.event_types.join(',')}`);
  return parts.length ? `&${parts.join('&')}` : '';
}

// Trending endpoints
export const trendingApi = {
  getTechniques: async (
    days: number = 90,
    limit: number = 15,
    filters: ActivityFilters = {},
  ): Promise<TrendingTechniquesResponse> => {
    const response = await api.get(
      `/trending/techniques?days=${days}&limit=${limit}${activityFilterParams(filters)}`,
    );
    return response.data;
  },

  getPlatforms: async (
    days: number = 90,
    limit: number = 15,
    filters: Omit<ActivityFilters, 'platforms'> = {},
  ): Promise<TrendingPlatformsResponse> => {
    // `platforms` would be circular here (it's the grouping key).
    const response = await api.get(
      `/trending/platforms?days=${days}&limit=${limit}${activityFilterParams(filters)}`,
    );
    return response.data;
  },

  getSummary: async (days: number = 90): Promise<TrendingSummaryResponse> => {
    const response = await api.get(`/trending/summary?days=${days}`);
    return response.data;
  },

  getUseCases: async (
    days: number = 90,
    limit: number = 15,
    filters: ActivityFilters = {},
  ): Promise<TrendingUseCasesResponse> => {
    const response = await api.get(
      `/trending/use-cases?days=${days}&limit=${limit}${activityFilterParams(filters)}`,
    );
    return response.data;
  },

  getWeeklyActivity: async (weeks: number = 12): Promise<WeeklyActivityResponse> => {
    const response = await api.get(`/trending/weekly-activity?weeks=${weeks}`);
    return response.data;
  },

  getRecentRules: async (
    limit: number = 20,
    filters: ActivityFilters = {},
    days?: number,
  ): Promise<RecentRulesResponse> => {
    const daysParam = days != null ? `&days=${days}` : '';
    const response = await api.get(
      `/trending/recent-rules?limit=${limit}${daysParam}${activityFilterParams(filters)}`,
    );
    return response.data;
  },

  getThreatPulse: async (
    limit: number = 8,
    days?: number,
  ): Promise<ThreatPulseResponse> => {
    // Pass `days` for a time-windowed pulse; omit for the full-catalog
    // scan. Backend caps at 7-730 — we don't enforce client-side; the
    // 422 from the API is informative enough.
    const params = new URLSearchParams({ limit: String(limit) });
    if (days != null) params.set('days', String(days));
    const response = await api.get(`/trending/threats?${params}`);
    return response.data;
  },
};

export interface RecentRuleItem {
  id: string;
  rule_id: string | null;
  title: string;
  source: string;
  severity: string;
  platforms: string[];
  event_types: string[];
  date: string | null;
}

export interface RecentRulesResponse {
  most_recently_created: RecentRuleItem[];
  most_recently_modified: RecentRuleItem[];
}

// Threat pulse — named threats (Splunk analytic_story + Sublime Malfam)
// and CVE mentions extracted across tags/title/description.
export interface ThreatExample {
  id: string;
  title: string;
  source: string;
}

export interface NamedThreat {
  name: string;
  kind: string; // "campaign" | "malware"
  count: number;
  sources: string[];
  examples: ThreatExample[];
}

export interface CveMention {
  cve: string;
  count: number;
  sources: string[];
  examples: ThreatExample[];
}

export interface ThreatPulseResponse {
  scope: 'window' | 'full_catalog';
  period_days: number | null;
  named_threats: NamedThreat[];
  cves: CveMention[];
}

export default api;
