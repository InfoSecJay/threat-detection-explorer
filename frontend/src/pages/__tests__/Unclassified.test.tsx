/**
 * /methodology/unclassified (#112): totals per field, one row per
 * source, every non-zero cell links to the catalog filtered to those
 * rules, and the sparkline shows the nightly trend.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Unclassified } from '../Unclassified';

vi.mock('../../services/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../services/api')>();
  return {
    ...actual,
    methodologyApi: {
      ...actual.methodologyApi,
      unclassified: vi.fn().mockResolvedValue({
        generated_at: '2026-09-02T00:00:00Z',
        fields: ['platforms', 'status'],
        catalog_filter_key: { platforms: 'platforms', status: 'statuses' },
        total_rules: 300,
        totals: { platforms: 12, status: 100 },
        sources: [
          { source: 'sigma', total_rules: 200, fields: { platforms: 0, status: 100 } },
          { source: 'splunk', total_rules: 100, fields: { platforms: 12, status: 0 } },
        ],
        history: [
          { date: '2026-08-31', total_rules: 290, fields: { platforms: 20, status: 100 } },
          { date: '2026-09-02', total_rules: 300, fields: { platforms: 12, status: 100 } },
        ],
      }),
    },
  };
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><MemoryRouter><Unclassified /></MemoryRouter></QueryClientProvider>,
  );
}

describe('Unclassified', () => {
  it('renders totals, per-source cells linking to the catalog, and the trend', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByTestId('unclassified-table')).toBeInTheDocument());
    expect(screen.getByTestId('unclassified-totals')).toHaveTextContent('12');
    expect(screen.getByTestId('unclassified-totals')).toHaveTextContent('4% of 300');

    const splunkCell = screen.getByTitle(/12 Splunk rules with unknown Platform/);
    expect(splunkCell).toHaveAttribute('href', '/detections?sources=splunk&platforms=unknown');
    // Zero cells are not links.
    expect(screen.queryByTitle(/0 Splunk rules/)).toBeNull();
    // Trend delta: platforms 20 -> 12.
    expect(screen.getByTitle('20 -> 12 over 2 days')).toHaveTextContent('-8');
  });
});
