import axios from 'axios';
import type {
  Detection,
  DetectionListResponse,
  Repository,
  SyncResponse,
  IngestionResponse,
  SearchFilters,
  CompareResponse,
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
    sources?: string[];
  }): Promise<CompareResponse> => {
    const searchParams = new URLSearchParams();
    if (params.technique) searchParams.set('technique', params.technique);
    if (params.keyword) searchParams.set('keyword', params.keyword);
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

export default api;
