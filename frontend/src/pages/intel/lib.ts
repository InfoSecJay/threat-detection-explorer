/**
 * Shared metadata + helpers for the Intel page sub-components.
 * Anything that's pure (no JSX, no hooks) lives here.
 */

import { parseApiDate } from '../../utils/dates';
import type { Release } from '../../services/api';

export const severityColor: Record<string, string> = {
  critical: 'text-red-400 border-red-500/40 bg-red-500/10',
  high: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  low: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
  informational: 'text-gray-400 border-gray-600/40 bg-void-800',
  unknown: 'text-gray-500 border-gray-600/40 bg-void-800',
};

export interface ReleaseWithSource extends Release {
  source: string;
}

/** Compact "today | 1d | 7d | 3mo | 2y" relative-time formatter. */
export function formatRelDate(iso: string | null): string {
  if (!iso) return '—';
  const d = parseApiDate(iso);
  const diffDays = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
  if (diffDays < 1) return 'today';
  if (diffDays === 1) return '1d';
  if (diffDays < 30) return `${diffDays}d`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo`;
  return `${Math.floor(diffDays / 365)}y`;
}

// Time-window options for the Intel page's global period toggle.
// One control drives Pulse, Threat Spotlight, What's New (both the
// newest-rules cards and the trending tiles). Repo Health + Upstream
// Releases sit outside this window because they're separate cadences.
export const periodOptions = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
];
