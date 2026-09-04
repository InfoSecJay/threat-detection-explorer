/**
 * /methodology/corpus-health (#124): headline percentages, one row per
 * source, a CSV download and a definition anchor for every number.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CorpusHealth } from '../CorpusHealth';

vi.mock('../../hooks/useCorpusHealth', () => ({
  useCorpusHealth: () => ({
    data: {
      generated_at: '2026-09-04T00:00:00Z',
      corpus: { rules: 300, updated_at: '2026-09-03 07:50:49' },
      fields: ['no_attack', 'no_references'],
      field_meta: {
        no_attack: { label: 'No ATT&CK mapping', definition: 'mitre_techniques is empty.' },
        no_references: { label: 'No references', definition: 'references is empty.' },
      },
      total_rules: 300,
      totals: { no_attack: 90, no_references: 150 },
      totals_pct: { no_attack: 30, no_references: 50 },
      applicable: { no_attack: { count: 90, of: 300, pct: 30 }, no_references: { count: 100, of: 200, pct: 50 } },
      sources: [
        { source: 'sigma', total_rules: 200, not_applicable: [], fields: { no_attack: 0, no_references: 100 }, pct: { no_attack: 0, no_references: 50 } },
        { source: 'splunk', total_rules: 100, not_applicable: ['no_references'], fields: { no_attack: 90, no_references: 0 }, pct: { no_attack: 90, no_references: null } },
      ],
    },
    isLoading: false,
    error: null,
  }),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><MemoryRouter><CorpusHealth /></MemoryRouter></QueryClientProvider>,
  );
}

describe('CorpusHealth', () => {
  it('renders the headline percentages, per-source rows, CSV link and definitions', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByTestId('corpus-health-table')).toBeInTheDocument());

    const totals = screen.getByTestId('corpus-health-totals');
    expect(totals).toHaveTextContent('30%');
    expect(totals).toHaveTextContent('90 of 300 rules');
    // Applicable basis when a format lacks the field, with the literal share underneath.
    expect(totals).toHaveTextContent('100 of 200 rules whose format has the field');
    expect(totals).toHaveTextContent('50% of all 300');

    // Per-source cell carries both the share and the count; zero cells stay plain; n/a is explained.
    expect(screen.getByTitle(/90 of 100 Splunk rules: No ATT&CK mapping/)).toHaveTextContent('90% 90');
    expect(screen.getByTitle(/0 of 200 Sigma rules: No ATT&CK mapping/)).toHaveTextContent('0');
    expect(screen.getByTitle(/Splunk: the rule format has no field for this/)).toHaveTextContent('n/a');

    expect(screen.getByTestId('corpus-health-csv')).toHaveAttribute('href', expect.stringContaining('/methodology/corpus-health.csv'));
    const defs = screen.getByTestId('corpus-health-definitions');
    expect(defs).toHaveTextContent('mitre_techniques is empty.');
    expect(defs).toHaveTextContent('Corpus health as of 2026-09-03 (300 rules, 2 sources)');
  });
});
