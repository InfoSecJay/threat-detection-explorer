/**
 * Map a typed observable (type/subtype from the canonical vocabulary)
 * to the observable page surface that indexes its values. Returns
 * null for subtypes with no page (command-line patterns, code
 * signatures, free-text...).
 */

export type ObservableKind =
  | 'process' | 'path' | 'registry' | 'network' | 'action' | 'eventid' | 'table' | 'resource';

export const OBSERVABLE_KIND_LABEL: Record<ObservableKind, string> = {
  process: 'Process',
  path: 'File path',
  registry: 'Registry key',
  network: 'Network indicator',
  action: 'API action',
  eventid: 'Event ID',
  table: 'Source table',
  resource: 'Target resource',
};

/** SearchFilters key for "open in catalog" per kind. */
export const OBSERVABLE_FILTER_KEY: Record<ObservableKind, string> = {
  process: 'process_names',
  path: 'file_paths',
  registry: 'registry_keys',
  network: 'network_indicators',
  action: 'api_actions',
  eventid: 'event_ids',
  table: 'source_tables',
  resource: 'target_resources',
};

export function kindFor(type: string, subtype: string): ObservableKind | null {
  switch (type) {
    case 'process':
      return subtype === 'process_name' || subtype === 'parent_process_name' ? 'process' : null;
    case 'file':
      return subtype === 'file_path' ? 'path' : null;
    case 'registry':
      return subtype === 'registry_key' || subtype === 'registry_value' ? 'registry' : null;
    case 'network':
      return subtype === 'ip_address' || subtype === 'domain' || subtype === 'url' ? 'network' : null;
    case 'dns':
      return subtype === 'query_name' ? 'network' : null;
    case 'email':
      return subtype === 'url' || subtype === 'sender_domain' ? 'network' : null;
    case 'cloud':
      if (subtype === 'api_action') return 'action';
      if (subtype === 'resource' || subtype === 'resource_type') return 'resource';
      return null;
    case 'identity':
      if (subtype === 'action') return 'action';
      if (subtype === 'target') return 'resource';
      return null;
    case 'event':
      return subtype === 'event_id' ? 'eventid' : null;
    default:
      return null;
  }
}

export function observableUrl(kind: ObservableKind, value: string): string {
  return `/observables/${kind}/${encodeURIComponent(value)}`;
}
