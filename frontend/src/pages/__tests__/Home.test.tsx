/**
 * Render test for the refreshed Home page: every data hook mocked in
 * its loaded shape, then asserts the composed sections show the live
 * numbers they are meant to (ticker cells, gap ranking, source cards).
 */

import { describe, it, vi, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../hooks/useDetections', () => ({
  useStatistics: () => ({
    data: {
      total: 15682,
      by_source: { sigma: 3783, splunk: 2156 },
      by_severity: {}, by_status: {},
      quality_avg: 57.3,
      quality_by_source: { sigma: { avg: 61.2, scored: 3783 } },
    },
    isLoading: false, error: null, refetch: () => {},
  }),
  useFacets: () => ({
    data: { quality_band: [{ value: '80', count: 100 }, { value: '60', count: 900 }, { value: '40', count: 4000 }] },
  }),
  useQueryFields: () => ({ data: { fields: [] } }),
  useFilterOptions: () => ({ data: undefined }),
}));

vi.mock('../../hooks/useTrending', () => ({
  useSourceDeltas: () => ({
    data: {
      days: 7, method: 'sync_jobs', current_job_id: 'j1', current_at: '2026-08-29T06:00:00Z',
      baseline_job_id: 'j0', baseline_at: '2026-08-22T06:00:00Z',
      by_source: { sigma: { current: 3783, baseline: 3771, delta: 12 }, splunk: { current: 2156, baseline: 2159, delta: -3 } },
    },
    isLoading: false, error: null,
  }),
  useNewlyCovered: () => ({
    data: {
      method: 'rule_dates', window_days: 7, baseline_date: null, new_sources: [],
      catalog_newly_covered: [{ technique_id: 'T1651', technique_name: 'Cloud Administration Command', sources: { splunk: 2 }, total_rules: 2 }],
      source_newly_covered: [],
    },
    isLoading: false, error: null,
  }),
  useTechniqueDeltas: () => ({
    data: {
      days: 7, method: 'snapshot', current_date: '2026-08-29', baseline_date: '2026-08-22',
      gainers: [{ technique_id: 'T1059', current: 19, baseline: 15, delta: 4, sources_added: [], sources_removed: [] }],
      losers: [],
    },
    isLoading: false, error: null,
  }),
}));

vi.mock('../../hooks/useRepositories', () => ({
  useRepositories: () => ({
    data: [{ id: '1', name: 'sigma', url: '', last_commit_hash: 'abc', last_sync_at: '2026-08-29T06:00:00Z', rule_count: 3783, status: 'idle', error_message: null, created_at: '' }],
    isLoading: false,
  }),
}));

vi.mock('../../hooks/useActors', () => ({
  useActorsQuery: () => ({
    data: {
      items: [
        { id: 'G0016', name: 'APT29', aliases: [], description: '', deprecated: false, modified: null, technique_count: 120, covered_technique_count: 80, our_rule_count: 40, mention_count: 3, sources_with_coverage: ['sigma'], weighted_coverage: 0.62, gap_count: 40, weighted_gap: 12.5, origin_country: 'RU' },
      ],
      total: 1, page: 1, per_page: 6, facets: {}, summary: { total_groups: 1, total_software: 0, groups_with_coverage: 1, software_with_coverage: 0 },
    },
    isLoading: false, error: null,
  }),
}));

vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({
    tactics: {}, techniques: {}, isLoading: false, error: null,
    getTacticName: (id: string) => id, getTechniqueName: (id: string) => id,
    getTacticUrl: () => '', getTechniqueUrl: () => '', refresh: async () => {},
  }),
}));

vi.mock('../../hooks/useSavedQueries', () => ({
  useSavedQueries: () => ({ recent: [], saved: [], recordRecent: () => {}, star: () => {}, unstar: () => {}, rename: () => {}, clearRecent: () => {} }),
}));

import { Home } from '../Home';

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Home />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Home', () => {
  it('renders the ticker with live corpus numbers', async () => {
    const { getByTestId } = renderPage();
    await waitFor(() => expect(getByTestId('ticker-rules')).toHaveTextContent('15,682'));
    expect(getByTestId('ticker-7d-net')).toHaveTextContent('+9');
    expect(getByTestId('ticker-newly-covered')).toHaveTextContent('1');
    expect(getByTestId('ticker-momentum')).toHaveTextContent('T1059 +4');
  });

  it('ranks gap actors and shows source cards with deltas', async () => {
    const { getByTestId, getByText } = renderPage();
    await waitFor(() => expect(getByTestId('gap-G0016')).toHaveTextContent('APT29'));
    expect(getByTestId('gap-G0016')).toHaveTextContent('40 / 120 uncovered');
    expect(getByTestId('source-sigma')).toHaveTextContent('3,783');
    expect(getByTestId('source-sigma')).toHaveTextContent('+12 / 7d');
    expect(getByTestId('source-sigma')).toHaveTextContent('hygiene 61.2');
    expect(getByText(/avg 57.3/)).toBeInTheDocument();
  });
});
