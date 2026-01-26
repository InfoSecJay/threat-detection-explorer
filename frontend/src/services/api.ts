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
    if (filters.sources?.length) params.set('sources', filters.sources.join(','));
    if (filters.statuses?.length) params.set('statuses', filters.statuses.join(','));
    if (filters.severities?.length) params.set('severities', filters.severities.join(','));
    if (filters.languages?.length) params.set('languages', filters.languages.join(','));
    if (filters.mitre_tactics?.length) params.set('mitre_tactics', filters.mitre_tactics.join(','));
    if (filters.mitre_techniques?.length) params.set('mitre_techniques', filters.mitre_techniques.join(','));
    if (filters.tags?.length) params.set('tags', filters.tags.join(','));
    if (filters.log_sources?.length) params.set('log_sources', filters.log_sources.join(','));
    // Standardized taxonomy filters
    if (filters.platforms?.length) params.set('platforms', filters.platforms.join(','));
    if (filters.event_categories?.length) params.set('event_categories', filters.event_categories.join(','));
    if (filters.data_sources_normalized?.length) params.set('data_sources_normalized', filters.data_sources_normalized.join(','));
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
  total_modified: number;
  by_source: Record<string, number>;
}

// Trending endpoints
export const trendingApi = {
  getTechniques: async (days: number = 90, limit: number = 15): Promise<TrendingTechniquesResponse> => {
    const response = await api.get(`/trending/techniques?days=${days}&limit=${limit}`);
    return response.data;
  },

  getPlatforms: async (days: number = 90, limit: number = 15): Promise<TrendingPlatformsResponse> => {
    const response = await api.get(`/trending/platforms?days=${days}&limit=${limit}`);
    return response.data;
  },

  getSummary: async (days: number = 90): Promise<TrendingSummaryResponse> => {
    const response = await api.get(`/trending/summary?days=${days}`);
    return response.data;
  },
};

export default api;
