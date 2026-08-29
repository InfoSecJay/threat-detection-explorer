import { describe, it, vi, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

const DIGEST = {
  generated_at: '2026-08-29T12:00:00Z',
  period: { days: 7, start: '2026-08-22T12:00:00Z', end: '2026-08-29T12:00:00Z' },
  summary: { total_rules: 15682, created: 41, modified: 120, created_by_source: { sigma: 30, splunk: 11 } },
  source_deltas: { days: 7, method: 'sync_jobs', current_job_id: 'j', current_at: null, baseline_job_id: 'b', baseline_at: null, by_source: { sigma: { current: 3783, baseline: 3753, delta: 30 } } },
  newly_covered: { method: 'rule_dates', window_days: 7, baseline_date: null, new_sources: [], catalog_newly_covered: [{ technique_id: 'T1651', technique_name: 'Cloud Administration Command', sources: { splunk: 2 }, total_rules: 2 }], source_newly_covered: [] },
  momentum: { days: 7, method: 'insufficient_history', current_date: '2026-08-29', baseline_date: null, gainers: [], losers: [] },
  new_rules: [{ id: 'r1', rule_id: null, title: 'Suspicious LSASS Access', source: 'sigma', severity: 'high', status: 'stable', platforms: [], event_types: [], mitre_techniques: ['T1003.001'], quality_score: 74, source_rule_url: null, created: '2026-08-28T10:00:00Z', modified: null, description: '' }],
  emerging_data_sources: [{ data_source: 'sysmon', count: 12, sources: ['sigma'] }],
};

vi.mock('../../hooks/useTrending', () => ({
  useDigest: () => ({ data: DIGEST, isLoading: false, error: null, refetch: () => {} }),
  useSourceDeltas: () => ({ data: DIGEST.source_deltas, isLoading: false }),
  useNewlyCovered: () => ({ data: DIGEST.newly_covered, isLoading: false }),
  useTechniqueDeltas: () => ({ data: DIGEST.momentum, isLoading: false, error: null }),
}));
vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ getTechniqueName: (id: string) => id, getTacticName: (id: string) => id, tactics: {}, techniques: {}, isLoading: false, error: null, getTacticUrl: () => '', getTechniqueUrl: () => '', refresh: async () => {} }),
}));

import { Digest } from '../Digest';

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter><Digest /></MemoryRouter></QueryClientProvider>);
}

describe('Digest', () => {
  it('renders the summary, new rules and a markdown rendering', async () => {
    const { getByTestId, getByLabelText, getByText } = renderPage();
    await waitFor(() => expect(getByTestId('digest-created')).toHaveTextContent('41'));
    expect(getByTestId('digest-rule-r1')).toHaveTextContent('Suspicious LSASS Access');
    expect(getByTestId('digest-rule-r1')).toHaveTextContent('74');
    const md = (getByLabelText('Digest as Markdown') as HTMLTextAreaElement).value;
    expect(md).toContain('# Detection Explorer digest - 2026-08-22 to 2026-08-29');
    expect(md).toContain('- SigmaHQ: +30 (now 3783)');
    expect(md).toContain('T1651 Cloud Administration Command - first rule anywhere (splunk)');
    expect(md).toContain('[sigma] Suspicious LSASS Access (high, T1003.001)');
    expect(getByText(/New detection rules/)).toBeInTheDocument();
  });
});
