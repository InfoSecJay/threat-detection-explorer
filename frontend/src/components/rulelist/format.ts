/** Presentation helpers shared by the catalog table cells. */

import { parseApiDate, daysSince } from '../../utils/dates';

// Color mappings
export const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-breach-500/10', text: 'text-breach-400', border: 'border-breach-500/30' },
  high: { bg: 'bg-threat-500/10', text: 'text-threat-400', border: 'border-threat-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-pulse-500/10', text: 'text-pulse-400', border: 'border-pulse-500/30' },
  unknown: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
};

// Sort options -- mirrors the clickable column headers below. Any
// field listed here must also appear in the backend
// _apply_sorting sort_columns map or the sort silently falls back
// to Title.
export const sortOptions = [
  { value: 'title:asc', label: 'Title (A-Z)' },
  { value: 'title:desc', label: 'Title (Z-A)' },
  { value: 'severity:desc', label: 'Severity (High to Low)' },
  { value: 'severity:asc', label: 'Severity (Low to High)' },
  { value: 'relevance:desc', label: 'Relevance' },
  { value: 'rule_created_date:desc', label: 'Created (Newest)' },
  { value: 'rule_created_date:asc', label: 'Created (Oldest)' },
  { value: 'rule_modified_date:desc', label: 'Modified (Newest)' },
  { value: 'rule_modified_date:asc', label: 'Modified (Oldest)' },
  { value: 'source:asc', label: 'Source (A-Z)' },
  { value: 'source:desc', label: 'Source (Z-A)' },
  { value: 'language:asc', label: 'Language (A-Z)' },
  { value: 'language:desc', label: 'Language (Z-A)' },
  { value: 'domains:asc', label: 'Domain (A-Z)' },
  { value: 'domains:desc', label: 'Domain (Z-A)' },
  { value: 'platforms:asc', label: 'Platform (A-Z)' },
  { value: 'platforms:desc', label: 'Platform (Z-A)' },
  { value: 'data_sources:asc', label: 'Data Source (A-Z)' },
  { value: 'data_sources:desc', label: 'Data Source (Z-A)' },
  { value: 'event_types:asc', label: 'Event Type (A-Z)' },
  { value: 'event_types:desc', label: 'Event Type (Z-A)' },
  { value: 'quality_score:desc', label: 'Completeness (Best first)' },
  { value: 'quality_score:asc', label: 'Completeness (Worst first)' },
];

// Hygiene-score band colors. The score measures rule hygiene
// (metadata, mapping, docs, testability), NOT detection efficacy.
export function qualityBand(score: number): string {
  if (score >= 80) return 'text-matrix-400 border-matrix-500/40 bg-matrix-500/10';
  if (score >= 60) return 'text-lime-400 border-lime-500/40 bg-lime-500/10';
  if (score >= 40) return 'text-amber-400 border-amber-500/40 bg-amber-500/10';
  return 'text-breach-400 border-breach-500/40 bg-breach-500/10';
}

export function formatRelativeDate(dateStr: string | null): string {
  // daysSince clamps at 0: a timestamp a few minutes ahead of the
  // viewer's clock used to fall through every branch and render "-1d".
  const diffDays = daysSince(dateStr);
  if (diffDays === null) return '-';

  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays}d`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)}w`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo`;
  return `${Math.floor(diffDays / 365)}y`;
}

export function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-';
  const date = parseApiDate(dateStr);
  if (isNaN(date.getTime())) return '-';
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}
