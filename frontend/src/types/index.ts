// Detection types
export type DetectionSource = 'sigma' | 'elastic' | 'splunk' | 'sublime' | 'elastic_protections' | 'lolrmm' | 'elastic_hunting' | 'sentinel' | 'google_secops' | 'okta' | 'auth0' | 'panther' | 'pypanther';

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
  // Sigma's maturity vocabulary, preserved 1:1 (issue #26).
  status: 'stable' | 'test' | 'experimental' | 'deprecated' | 'unsupported' | 'unknown';
  // Building-block / signal-only rule: feeds other rules instead of
  // alerting on its own (Elastic building_block_type, Panther
  // CreateAlert: false). Orthogonal to status.
  is_building_block: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  // Canonical taxonomy (Phase 3 final names). See docs/taxonomy.md.
  // The legacy single-value siblings (platform / event_category /
  // data_source_normalized) and the raw vendor lists (log_sources,
  // a separate raw `data_sources`) were dropped in Phase 3.
  platforms: string[];
  data_sources: string[];
  event_types: string[];
  // Vendor-preserved analytic story / use-case labels. Populated for
  // Splunk (analytic_story), Elastic (Use Case: tags), Sublime
  // (attack_types); empty on sources without a native concept.
  use_cases?: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  // Raw ATT&CK Group + Software IDs (e.g. "G0016", "S0002"). Display
  // names come from mitreLookup.ts on the FE — unknown IDs render as
  // the raw ID.
  mitre_groups?: string[];
  mitre_software?: string[];
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
  // Hygiene score (issue #10) — rule hygiene, NOT detection efficacy.
  quality_score?: number | null;
  quality_details?: QualityDetails | null;
  created_at: string;  // Sync timestamp
  updated_at: string;  // Sync timestamp
}

export interface QualityDimension {
  score: number;
  of: number;
  issues: string[];
}

export interface QualityDetails {
  version: number;
  total: number;
  dimensions: Record<string, QualityDimension>;
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
  // Lucene-syntax query. Parsed server-side via luqum; malformed
  // queries surface as HTTP 400 with an inline error under the bar.
  // See /query for syntax + field reference.
  q?: string;
  sources?: string[];
  statuses?: string[];
  // Tri-state: true = building blocks only, false = hide them,
  // undefined = both (issue #26).
  building_block?: boolean;
  // Minimum hygiene score (0-100), inclusive (#39).
  min_quality?: number;
  severities?: string[];
  languages?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  mitre_groups?: string[];
  mitre_software?: string[];
  tags?: string[];
  // Canonical taxonomy filters (Phase 3 final names; the
  // `event_categories` / `data_sources_normalized` keys retained
  // for URL backwards-compat with FilterPanel UI).
  platforms?: string[];
  event_categories?: string[];
  data_sources_normalized?: string[];
  // Analytic story / vendor use-case labels
  use_cases?: string[];
  // Extracted observable filters
  event_ids?: string[];
  process_names?: string[];
  query_complexity?: string[];
  api_actions?: string[];
  file_paths?: string[];
  registry_keys?: string[];
  network_indicators?: string[];
  target_resources?: string[];
  source_tables?: string[];
  offset?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// Statistics types
export interface Statistics {
  total: number;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  // Hygiene averages over scored rows (#39); absent on older responses.
  quality_avg?: number | null;
  quality_by_source?: Record<string, { avg: number; scored: number }>;
}

// Export types
export interface ExportRequest {
  format: 'json' | 'csv' | 'navigator';
  filters?: SearchFilters;
  ids?: string[];
  include_raw?: boolean;
}
