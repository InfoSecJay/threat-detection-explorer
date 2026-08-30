import { describe, it, vi, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

vi.mock('../../hooks/useObservables', () => ({
  useObservableProfile: () => ({
    data: {
      type: 'process', label: 'Process', value: 'mimikatz.exe', filter_key: 'process_names',
      total_rules: 3, negated_in: 1,
      by_source: { sigma: 2, splunk: 1 }, by_severity: { high: 2, critical: 1 }, by_platform: { windows: 3 },
      by_technique: [{ technique_id: 'T1003.001', rules: 3 }], by_tactic: [{ tactic_id: 'TA0006', rules: 3 }],
      fields: [{ field: 'Image', rules: 2 }],
      co_occurring: { eventid: [{ value: '10', rules: 2 }], process: [{ value: 'lsass.exe', rules: 2 }] },
      rules: [{ id: 'r1', title: 'Mimikatz Execution', source: 'sigma', severity: 'high', status: 'stable', mitre_techniques: ['T1003.001'], quality_score: 81, created: null }],
    },
    isLoading: false, error: null,
  }),
}));
vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ getTechniqueName: () => 'OS Credential Dumping: LSASS Memory', getTacticName: () => 'Credential Access', tactics: {}, techniques: {}, isLoading: false, error: null, getTacticUrl: () => '', getTechniqueUrl: () => '', refresh: async () => {} }),
}));
vi.mock('../../hooks/useEventIds', () => ({ useEventIds: () => ({ labels: {}, entries: {} }) }));

import { ObservableDetail } from '../ObservableDetail';

describe('ObservableDetail', () => {
  it('renders the profile for a value with slashes-safe routing', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { getByTestId, getByText } = render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/observables/process/mimikatz.exe']}>
          <Routes><Route path="/observables/:kind/*" element={<ObservableDetail />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await waitFor(() => expect(getByTestId('observable-value')).toHaveTextContent('mimikatz.exe'));
    expect(getByTestId('observable-total')).toHaveTextContent('3');
    expect(getByText(/OS Credential Dumping/)).toBeInTheDocument();
    expect(getByText('lsass.exe')).toBeInTheDocument();
    expect(getByTestId('obs-rule-r1')).toHaveTextContent('Mimikatz Execution');
    expect(getByText(/as exclusion/)).toBeInTheDocument();
  });
});
