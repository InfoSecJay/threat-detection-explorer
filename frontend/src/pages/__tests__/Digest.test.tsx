import { describe, it, vi, expect } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

const DIGEST = {
  generated_at: '2026-08-29T12:00:00Z',
  period: { days: 7, start: '2026-08-22T12:00:00Z', end: '2026-08-29T12:00:00Z' },
  summary: {
    total_rules: 15682, created: 41, modified: 120, created_by_source: { sigma: 30, splunk: 11 },
    by_source: { sigma: { created: 30, modified: 100 }, splunk: { created: 11, modified: 20 } },
  },
  themes: [{ technique_id: 'T1003.001', technique_name: 'LSASS Memory', tactic: 'Credential Access', rules: 9, sources: { sigma: 6, splunk: 3 }, samples: [{ id: 'r1', title: 'Suspicious LSASS Access', source: 'sigma' }] }],
  source_deltas: { days: 7, method: 'sync_jobs', current_job_id: 'j', current_at: null, baseline_job_id: 'b', baseline_at: null, by_source: { sigma: { current: 3783, baseline: 3753, delta: 30 } } },
  newly_covered: { method: 'rule_dates', window_days: 7, baseline_date: null, new_sources: [], catalog_newly_covered: [{ technique_id: 'T1651', technique_name: 'Cloud Administration Command', sources: { splunk: 2 }, total_rules: 2 }], source_newly_covered: [] },
  momentum: { days: 7, method: 'insufficient_history', current_date: '2026-08-29', baseline_date: null, gainers: [], losers: [] },
  new_rules: [
    { id: 'r1', rule_id: null, title: 'Suspicious LSASS Access', source: 'sigma', severity: 'high', status: 'stable', platforms: ['windows'], event_types: [], mitre_techniques: ['T1003.001'], quality_score: 74, source_rule_url: 'https://github.com/SigmaHQ/sigma/blob/master/x.yml', created: '2026-08-28T10:00:00Z', modified: null, description: 'Detects handles opened on lsass.exe by unusual processes.' },
    { id: 'r2', rule_id: null, title: 'AWS Root Console Login', source: 'splunk', severity: 'medium', status: 'stable', platforms: ['aws'], event_types: [], mitre_techniques: ['T1078.004'], quality_score: null, source_rule_url: null, created: '2026-08-27T10:00:00Z', modified: null, description: '' },
  ],
  modified_rules: [
    { id: 'r3', rule_id: null, title: 'Mofcomp Execution', source: 'sigma', severity: 'medium', status: 'stable', platforms: ['windows'], event_types: [], mitre_techniques: ['T1047'], quality_score: 60, source_rule_url: null, created: '2025-01-01T00:00:00Z', modified: '2026-08-26T10:00:00Z', description: '' },
  ],
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
  it('leads with new vs updated counts and a per-source table of contents', async () => {
    const { getByTestId } = renderPage();
    await waitFor(() => expect(getByTestId('digest-created')).toHaveTextContent('41'));
    expect(getByTestId('digest-modified')).toHaveTextContent('120');
    expect(getByTestId('toc-sigma')).toHaveTextContent('+30');
    expect(getByTestId('toc-sigma')).toHaveTextContent('~100');
    expect(getByTestId('toc-sigma')).toHaveAttribute('href', '#src-sigma');
    expect(getByTestId('theme-T1003.001')).toHaveTextContent('LSASS Memory');
    expect(getByTestId('theme-T1003.001')).toHaveTextContent('Credential Access');
  });

  it('separates new rules (cards) from updated rules (list) per source', async () => {
    const { getByTestId } = renderPage();
    await waitFor(() => expect(getByTestId('digest-source-sigma')).toBeInTheDocument());
    const sigma = getByTestId('digest-source-sigma');
    expect(sigma).toHaveTextContent('+30 new');
    expect(sigma).toHaveTextContent('~100 updated');
    expect(getByTestId('digest-rule-r1')).toHaveTextContent('Detects handles opened on lsass.exe');
    expect(getByTestId('digest-rule-r1')).toHaveTextContent('hyg 74');
    expect(getByTestId('digest-updated-r3')).toHaveTextContent('Mofcomp Execution');
    expect(getByTestId('digest-updated-r3')).toHaveTextContent('2026-08-26');
    // capped lists say how many are not listed
    expect(sigma).toHaveTextContent('29 more not listed');
    expect(getByTestId('digest-source-splunk')).toHaveTextContent('AWS Root Console Login');
  });

  it('renders the same structure as markdown', async () => {
    const { getByLabelText, getByText } = renderPage();
    await waitFor(() => expect(getByLabelText('Digest as Markdown')).toBeInTheDocument());
    const md = (getByLabelText('Digest as Markdown') as HTMLTextAreaElement).value;
    expect(md).toContain('# Detection Explorer digest - 2026-08-22 to 2026-08-29');
    expect(md).toContain('41 new and 120 updated rules across 2 sources');
    expect(md).toContain('## Themes');
    expect(md).toContain('## SigmaHQ (+30, ~100)');
    expect(md).toContain('### New rules');
    expect(md).toContain('### Updated rules');
    expect(md).toContain('- Mofcomp Execution (2026-08-26)');
    expect(md).toContain('T1651 Cloud Administration Command - first rule anywhere (splunk)');
    expect(getByText('Updated rules', { selector: 'span' })).toBeInTheDocument();
  });
});
