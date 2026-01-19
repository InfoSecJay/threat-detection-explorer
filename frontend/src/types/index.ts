// Detection types
export interface Detection {
  id: string;
  source: 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm';
  source_file: string;
  source_repo_url: string;
  source_rule_url: string | null;
  rule_id: string | null;
  title: string;
  description: string | null;
  author: string | null;
  status: 'stable' | 'experimental' | 'deprecated' | 'unknown';
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  log_sources: string[];
  data_sources: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  detection_logic: string;
  tags: string[];
  references: string[];
  false_positives: string[];
  raw_content?: string;
  rule_created_date: string | null;
  rule_modified_date: string | null;
  created_at: string;  // Sync timestamp
  updated_at: string;  // Sync timestamp
}

export interface DetectionListResponse {
  items: Detection[];
  total: number;
  offset: number;
  limit: number;
}

// Repository types
export interface Repository {
  id: string;
  name: string;
  url: string;
  last_commit_hash: string | null;
  last_sync_at: string | null;
  rule_count: number;
  status: 'idle' | 'syncing' | 'error';
  error_message: string | null;
  created_at: string;
}

export interface SyncResponse {
  success: boolean;
  message: string;
  repository: string | null;
}

export interface IngestionError {
  file_path: string;
  stage: 'discovery' | 'read' | 'parse' | 'normalize' | 'store';
  severity: 'warning' | 'error';
  message: string;
  details: string | null;
  timestamp: string;
}

export interface IngestionStats {
  discovered: number;
  skipped_by_filter: number;
  parsed: number;
  normalized: number;
  stored: number;
  error_count: number;
  warning_count: number;
  success_rate: number;
  duration_seconds: number | null;
  errors_by_stage: Record<string, IngestionError[]>;
  sample_errors: IngestionError[];
}

export interface IngestionResponse {
  success: boolean;
  message: string;
  stats: IngestionStats;
}

// Search types
export interface SearchFilters {
  search?: string;
  sources?: string[];
  statuses?: string[];
  severities?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
  log_sources?: string[];
  offset?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// Compare types
export interface CompareResponse {
  query_type: 'technique' | 'keyword';
  query_value: string;
  results: Record<string, Detection[]>;
  total_by_source: Record<string, number>;
}

// Statistics types
export interface Statistics {
  total: number;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
}

// Export types
export interface ExportRequest {
  format: 'json' | 'csv';
  filters?: SearchFilters;
  ids?: string[];
  include_raw?: boolean;
}
