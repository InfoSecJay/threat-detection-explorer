/**
 * Centralized source, severity, and color constants for the app.
 * Import from here instead of duplicating maps across components.
 */

export const ALL_SOURCES = [
  'sigma',
  'elastic',
  'splunk',
  'sublime',
  'elastic_protections',
  'lolrmm',
  'elastic_hunting',
  'sentinel',
] as const;

export type SourceName = (typeof ALL_SOURCES)[number];

export const sourceColors: Record<string, string> = {
  sigma: '#a855f7',
  elastic: '#3b82f6',
  splunk: '#f97316',
  sublime: '#ec4899',
  elastic_protections: '#06b6d4',
  lolrmm: '#22c55e',
  elastic_hunting: '#8b5cf6',
  sentinel: '#0078d4',
};

export const sourceLabels: Record<string, string> = {
  sigma: 'Sigma',
  elastic: 'Elastic',
  splunk: 'Splunk',
  sublime: 'Sublime',
  elastic_protections: 'Elastic Protections',
  lolrmm: 'LOLRMM',
  elastic_hunting: 'Elastic Hunting',
  sentinel: 'Sentinel',
};

export const sourceLabelsShort: Record<string, string> = {
  sigma: 'SIGMA',
  elastic: 'ELASTIC',
  splunk: 'SPLUNK',
  sublime: 'SUBLIME',
  elastic_protections: 'EL_PROTECT',
  lolrmm: 'LOLRMM',
  elastic_hunting: 'EL_HUNT',
  sentinel: 'SENTINEL',
};

export const sourceTailwind: Record<string, string> = {
  sigma: 'border-purple-500 bg-purple-500/10',
  elastic: 'border-blue-500 bg-blue-500/10',
  splunk: 'border-orange-500 bg-orange-500/10',
  sublime: 'border-pink-500 bg-pink-500/10',
  elastic_protections: 'border-cyan-500 bg-cyan-500/10',
  lolrmm: 'border-green-500 bg-green-500/10',
  elastic_hunting: 'border-violet-500 bg-violet-500/10',
  sentinel: 'border-blue-400 bg-blue-400/10',
};

export const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  unknown: '#6b7280',
};

export const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export const severityTailwind: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/15 text-green-400 border-green-500/30',
  unknown: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
};
