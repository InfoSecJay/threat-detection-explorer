// Detection types
export type DetectionSource = 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting' | 'sentinel' | 'google_secops' | 'okta' | 'auth0';

export interface Detection {
  id: string;
  source: DetectionSource;
  source_file: string;
  source_repo_url: string;
  source_rule_url: string | null;
  rule_id: string | null;
  title: string;
  description: string | null;
  author: string | null;
  status: 'stable' | 'experimental' | 'deprecated' | 'unknown';
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  // Canonical taxonomy (Phase 3 final names). See docs/taxonomy.md.
  // The legacy single-value siblings (platform / event_category /
  // data_source_normalized) and the raw vendor lists (log_sources,
  // a separate raw `data_sources`) were dropped in Phase 3.
  platforms: string[];
  data_sources: string[];
  event_types: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  detection_logic: string;
  language: string;
  tags: string[];
  references: string[];
  false_positives: string[];
  // Extracted observable fields
  extracted_fields_used: string[];
  extracted_event_ids: string[];
  extracted_process_names: string[];
  extracted_file_paths: string[];
  extracted_registry_keys: string[];
  extracted_network_indicators: string[];
  extracted_source_tables: string[];
  extracted_observables: Array<{
    field: string;
    values: string[];
    type: string;
    subtype: string;
    negated: boolean;
  }>;
  query_complexity: string;
  extracted_api_actions: string[];
  extracted_target_resources: string[];
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
  languages?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
  // Canonical taxonomy filters (Phase 3 final names; the
  // `event_categories` / `data_sources_normalized` keys retained
  // for URL backwards-compat with FilterPanel UI).
  platforms?: string[];
  event_categories?: string[];
  data_sources_normalized?: string[];
  // Extracted field filters
  event_ids?: string[];
  process_names?: string[];
  query_complexity?: string[];
  api_actions?: string[];
  offset?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// Compare types
export interface CompareResponse {
  query_type: 'technique' | 'keyword' | 'platform';
  query_value: string;
  results: Record<string, Detection[]>;
  total_by_source: Record<string, number>;
}

export interface SideBySideResponse {
  detections: Detection[];
  field_comparison: Record<string, (string | null)[]>;
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
