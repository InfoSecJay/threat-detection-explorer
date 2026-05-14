// Detection types
export type DetectionSource = 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting' | 'sentinel' | 'google_secops' | 'okta';

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
  log_sources: string[];
  data_sources: string[];
  // Standardized log source taxonomy (legacy — to be removed in Phase 3)
  platform: string;  // windows, linux, macos, cloud, network, email
  event_category: string;  // process, file, network, registry, authentication, etc.
  data_source_normalized: string;  // sysmon, auditd, cloudtrail, etc.
  // Canonical taxonomy (Issue 2). See docs/taxonomy.md.
  taxonomy_platforms?: string[];
  taxonomy_data_sources?: string[];
  taxonomy_event_types?: string[];
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
  log_sources?: string[];
  // Standardized taxonomy filters
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
