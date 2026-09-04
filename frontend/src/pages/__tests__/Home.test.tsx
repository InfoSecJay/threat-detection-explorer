/**
 * Render test for the Home entry point: every data hook mocked in its
 * loaded shape, then asserts the hero numbers, the source tiles and
 * the three showcase cards show the live values they are meant to.
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
  useFacets: () => ({ data: undefined }),
  useQueryFields: () => ({ data: { fields: [] } }),
  useFilterOptions: () => ({ data: undefined }),
}));

vi.mock('../../hooks/useCompare', () => ({
  useCoverageMatrix: () => ({
    data: {
      sources: ['sigma', 'splunk'],
      tactics: [],
      summary: { total_tactics: 14, total_techniques: 203, techniques_with_any_coverage: 171, overall_coverage_percent: 84, source_coverage: {} },
    },
    isLoading: false, error: null,
  }),
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
}));

vi.mock('../../hooks/useRepositories', () => ({
  useRepositories: () => ({
    data: [
      { id: '1', name: 'sigma', url: '', last_commit_hash: 'abc', last_sync_at: '2026-08-29T06:00:00Z', rule_count: 3783, status: 'idle', error_message: null, created_at: '' },
      { id: '2', name: 'splunk', url: '', last_commit_hash: 'def', last_sync_at: '2026-08-28T06:00:00Z', rule_count: 2156, status: 'idle', error_message: null, created_at: '' },
    ],
    isLoading: false,
  }),
}));

vi.mock('../../hooks/useActors', () => ({
  useActorsQuery: () => ({
    data: {
      items: [
        { id: 'G0016', name: 'APT29', aliases: [], description: '', deprecated: false, modified: null, technique_count: 120, covered_technique_count: 80, our_rule_count: 40, mention_count: 3, sources_with_coverage: ['sigma'], weighted_coverage: 0.62, gap_count: 40, weighted_gap: 12.5, origin_country: 'RU' },
      ],
      total: 1, page: 1, per_page: 1, facets: {}, summary: { total_groups: 1, total_software: 0, groups_with_coverage: 1, software_with_coverage: 0 },
    },
    isLoading: false, error: null,
  }),
}));

vi.mock('../../hooks/useCorpusHealth', () => ({
  useCorpusHealth: () => ({
    data: {
      generated_at: '2026-09-04T00:00:00Z', corpus: { rules: 15682, updated_at: '2026-09-03 07:50:49' },
      fields: ['no_attack'], field_meta: { no_attack: { label: 'No ATT&CK mapping', definition: 'x' } },
      total_rules: 15682, totals: { no_attack: 4500 }, totals_pct: { no_attack: 28.7 }, sources: [],
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
  it('states scope in the hero and shows the four exact numbers', async () => {
    const { getByTestId, getByText } = renderPage();
    await waitFor(() => expect(getByTestId('stat-rules')).toHaveTextContent('15,682'));
    expect(getByText(/15,682 detection rules from 13 open-source/)).toBeInTheDocument();
    expect(getByTestId('stat-sources')).toHaveTextContent('13');
    expect(getByTestId('stat-coverage')).toHaveTextContent('171 / 203');
    // Parent-only figure; the MITRE browser defaults to parents + subs,
    // so the label must name the denominator.
    expect(getByTestId('stat-coverage')).toHaveTextContent(/parent techniques/i);
    expect(getByTestId('stat-sync')).not.toHaveTextContent('—');
  });

  it('lists every source with its live count and format', async () => {
    const { getByTestId } = renderPage();
    await waitFor(() => expect(getByTestId('source-sigma')).toHaveTextContent('3,783'));
    expect(getByTestId('source-sigma')).toHaveTextContent('Sigma YAML');
    expect(getByTestId('source-splunk')).toHaveTextContent('2,156');
    expect(getByTestId('source-google_secops')).toHaveTextContent('YARA-L');
    expect(getByTestId('source-google_secops')).toHaveTextContent('—'); // no count in fixture
  });

  it('showcases ATT&CK, actors and intel with one live fact each', async () => {
    const { getByTestId } = renderPage();
    await waitFor(() => expect(getByTestId('card-mitre-fact')).toHaveTextContent('84%'));
    expect(getByTestId('card-mitre-fact')).toHaveTextContent('171 / 203');
    expect(getByTestId('card-actors-fact')).toHaveTextContent('APT29');
    expect(getByTestId('card-actors-fact')).toHaveTextContent('40 of 120 techniques uncovered');
    expect(getByTestId('card-intel-fact')).toHaveTextContent('+9 rules net');
    expect(getByTestId('card-mitre')).toHaveAttribute('href', '/mitre');
    expect(getByTestId('card-actors')).toHaveAttribute('href', '/actors');
    expect(getByTestId('card-intel')).toHaveAttribute('href', '/intel');
  });
});
