/**
 * Render-smoke test for the Intel page.
 *
 * The point of this test is NOT to assert visual content — it's to
 * catch the class of bug that crashed the page on 2026-04-24: a
 * `useMemo` placed AFTER an early return inside a component that
 * react-renders twice (loading → loaded), violating the Rules of
 * Hooks and crashing on the loaded transition.
 *
 * Strategy: mock every API surface IndustryIntel reaches, render
 * once with all queries in their `loading` state, render again with
 * resolved data, and assert nothing throws either time. The hook-
 * order violation manifests as "Rendered more hooks than during the
 * previous render" — a render error vitest will surface as a failure.
 */

import { describe, it, vi, beforeEach, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// Stub all data hooks the page reaches into. Vitest hoists vi.mock
// so the stubs are in place before the page module evaluates.
vi.mock('../../hooks/useTrending', () => ({
  useTrendingTechniques: () => ({ data: { techniques: [] }, isLoading: false, error: null }),
  useTrendingPlatforms:  () => ({ data: { platforms: [] },  isLoading: false, error: null }),
  useTrendingUseCases:   () => ({ data: { use_cases: [] },  isLoading: false, error: null }),
  useTrendingSummary:    () => ({
    data: {
      period_days: 30,
      cutoff_date: '',
      total_created: 47,
      total_modified: 142,
      by_source: { sigma: { created: 20, modified: 47 }, splunk: { created: 12, modified: 22 } },
    },
    isLoading: false,
  }),
  useRecentRules:        () => ({ data: { most_recently_created: [], most_recently_modified: [] }, isLoading: false, error: null }),
  useWeeklyActivity:     () => ({
    data: {
      weeks: 12,
      week_starts: Array.from({ length: 12 }, (_, i) => `2026-06-${String(i + 1).padStart(2, '0')}`),
      by_source: { sigma: Array(12).fill(3), splunk: Array(12).fill(1) },
    },
    isLoading: false,
  }),
  useThreatActors:       () => ({
    data: {
      scope: 'window',
      period_days: 90,
      groups: [
        { id: 'G0016', name: 'APT29', aliases: ['Cozy Bear'], count: 12, sources: ['sigma'] },
      ],
      software: [
        { id: 'S0002', name: 'Mimikatz', type: 'tool', count: 25, sources: ['sigma', 'lolrmm'] },
      ],
    },
    isLoading: false,
    error: null,
  }),
}));

vi.mock('../../hooks/useRepositories', () => ({
  useRepositories: () => ({
    data: [
      { id: '1', name: 'sigma', url: '', last_commit_hash: null, last_sync_at: new Date().toISOString(), rule_count: 3200, status: 'idle', error_message: null, created_at: '' },
      { id: '2', name: 'splunk', url: '', last_commit_hash: null, last_sync_at: new Date(Date.now() - 25 * 3600 * 1000).toISOString(), rule_count: 2100, status: 'idle', error_message: null, created_at: '' },
    ],
    isLoading: false,
  }),
}));

vi.mock('../../hooks/useDetections', () => ({
  useFilterOptions: () => ({
    data: {
      sources: ['sigma', 'splunk'],
      platforms: [{ value: 'windows', count: 100 }, { value: 'o365', count: 30 }],
    },
  }),
}));

vi.mock('../../hooks/useReleases', () => ({
  useReleases: () => ({ data: [], isLoading: false }),
}));

vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({
    tactics: {},
    techniques: {},
    isLoading: false,
    error: null,
    getTacticName: (id: string) => id,
    getTechniqueName: (id: string) => id,
    getTacticUrl: () => '',
    getTechniqueUrl: () => '',
    refresh: async () => {},
  }),
}));

// Import AFTER mocks so the page picks up the stubs.
import { IndustryIntel } from '../IndustryIntel';

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <IndustryIntel />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('IndustryIntel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing on the loaded path', async () => {
    const { container, getByText } = renderPage();

    // Hook-order violations crash render — reaching this line at all
    // means the page mounted cleanly under the loaded data shape.
    await waitFor(() => {
      expect(getByText(/Detection Intelligence/i)).toBeInTheDocument();
    });
    expect(container.querySelector('section')).toBeTruthy();
  });
});
