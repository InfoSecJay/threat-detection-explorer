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

// Detection endpoints
export const detectionsApi = {
  list: async (filters: SearchFilters = {}): Promise<DetectionListResponse> => {
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
    if (filters.offset !== undefined) params.set('offset', String(filters.offset));
    if (filters.limit !== undefined) params.set('limit', String(filters.limit));
    if (filters.sort_by) params.set('sort_by', filters.sort_by);
    if (filters.sort_order) params.set('sort_order', filters.sort_order);

    const response = await api.get(`/detections?${params.toString()}`);
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
  technique_count: number;         // known techniques from MITRE
  covered_technique_count: number; // raw: how many have any rules (detail-page metric)
  our_rule_count: number;          // rules tagged with this G-ID (exact match)
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
  weighted_coverage: number | null;
  gap_count: number;
  weighted_gap: number;
  platforms: string[];
  technique_count: number;
  covered_technique_count: number;
  our_rule_count: number;
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

export const actorsApi = {
  list: async (): Promise<ActorsListResponse> => {
    const response = await api.get('/actors');
    return response.data;
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
