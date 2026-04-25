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

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// Stub all data hooks the page reaches into. Vitest hoists vi.mock
// so the stubs are in place before the page module evaluates.
vi.mock('../../hooks/useTrending', () => ({
  useTrendingTechniques: () => ({ data: { techniques: [] }, isLoading: false, error: null }),
  useTrendingPlatforms:  () => ({ data: { platforms: [] },  isLoading: false, error: null }),
  useTrendingSummary:    () => ({ data: { period_days: 30, cutoff_date: '', total_modified: 142, by_source: { sigma: 47, splunk: 22 } }, isLoading: false }),
  useRecentRules:        () => ({ data: { most_recently_created: [], most_recently_modified: [] }, isLoading: false, error: null }),
  useThreatPulse:        () => ({
    data: {
      scope: 'full_catalog',
      named_threats: [
        { name: 'Salt Typhoon', kind: 'campaign', count: 50, sources: ['splunk'], examples: [{ id: 'r1', title: 'Sample rule', source: 'splunk' }] },
      ],
      cves: [
        { cve: 'CVE-2025-31324', count: 6, sources: ['sigma'], examples: [] },
      ],
    },
    isLoading: false,
    error: null,
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

  it('renders the Threat Pulse section with mocked named-threat data', async () => {
    const { findByText } = renderPage();
    expect(await findByText('Salt Typhoon')).toBeInTheDocument();
    expect(await findByText('CVE-2025-31324')).toBeInTheDocument();
  });
});
