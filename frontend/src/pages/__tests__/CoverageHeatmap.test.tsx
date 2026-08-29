import { describe, it, vi, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../services/api', async () => {
  const actual = await vi.importActual<typeof import('../../services/api')>('../../services/api');
  return {
    ...actual,
    actorsApi: {
      ...actual.actorsApi,
      coverageMatrix: async () => ({
        kind: 'groups', sort: 'weighted_gap', limit: 40, total_entities: 2,
        sources: ['sigma', 'splunk', 'elastic'],
        source_totals: { sigma: 2, splunk: 1, elastic: 0 },
        rows: [
          { id: 'G0016', name: 'APT29', kind: 'groups', technique_count: 100, covered_technique_count: 60, gap_count: 40, weighted_gap: 12, weighted_coverage: 0.6,
            by_source: { sigma: { techniques_covered: 55, rule_count: 300 }, splunk: { techniques_covered: 20, rule_count: 40 } } },
          { id: 'G0007', name: 'APT28', kind: 'groups', technique_count: 80, covered_technique_count: 20, gap_count: 60, weighted_gap: 20, weighted_coverage: 0.25,
            by_source: { sigma: { techniques_covered: 20, rule_count: 50 } } },
        ],
      }),
    },
  };
});

import { CoverageHeatmap } from '../actors/CoverageHeatmap';

describe('CoverageHeatmap', () => {
  it('renders a row per actor with per-source coverage cells', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { getByTestId } = render(
      <QueryClientProvider client={qc}><MemoryRouter><CoverageHeatmap /></MemoryRouter></QueryClientProvider>,
    );
    await waitFor(() => expect(getByTestId('heat-G0016')).toHaveTextContent('APT29'));
    expect(getByTestId('heat-G0016')).toHaveTextContent('60%'); // any-source coverage
    expect(getByTestId('heat-G0016')).toHaveTextContent('55%'); // sigma cell
    expect(getByTestId('heat-G0016')).toHaveTextContent('20%'); // splunk cell
    expect(getByTestId('heat-G0007')).toHaveTextContent('-'); // elastic gap
  });
});
