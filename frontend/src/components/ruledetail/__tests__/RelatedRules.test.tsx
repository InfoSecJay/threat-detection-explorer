/**
 * DX-02: "Same behaviour, other vendors" must only ever list rules that
 * share a real observable with the current rule. A shared ATT&CK
 * technique alone renders in a separate, collapsed group instead.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RelatedRules } from '../RelatedRules';
import { detectionsApi } from '../../../services/api';
import type { RelatedRulesResponse } from '../../../services/api';

vi.mock('../../../services/api', () => ({
  detectionsApi: { related: vi.fn() },
}));

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><RelatedRules id="sigma:1" /></MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('RelatedRules', () => {
  it('lists an observable match under "same behaviour" and a technique-only match in the collapsed group', async () => {
    const response: RelatedRulesResponse = {
      id: 'sigma:1',
      related: [{
        id: 'sentinel:1', title: 'Suspicious named pipes', source: 'sentinel', severity: 'high', language: 'kql',
        quality_score: 80, score: 4, other_vendor: true, reasons: ['process rundll32.exe', 'technique T1055'],
      }],
      same_source: [],
      technique_only: [{
        id: 'elastic:1', title: 'Generic Memory Threat Detected', source: 'elastic', severity: 'medium', language: 'eql',
        quality_score: 60, score: 1, other_vendor: true, reasons: ['technique T1055'],
      }],
    };
    (detectionsApi.related as ReturnType<typeof vi.fn>).mockResolvedValue(response);
    renderPanel();

    await waitFor(() => expect(screen.getByTestId('related-sentinel:1')).toBeInTheDocument());
    expect(screen.getByText('Suspicious named pipes')).toBeInTheDocument();
    // The technique-only row gets its own row test id, never the main
    // list's `related-{id}` -- it must not be findable as a main-list row.
    expect(screen.queryByTestId('related-elastic:1')).not.toBeInTheDocument();

    const group = screen.getByTestId('related-technique-only');
    expect(group).toHaveTextContent('Shares an ATT&CK technique (1)');
    expect(screen.getByTestId('related-tech-only-elastic:1')).toHaveTextContent('Generic Memory Threat Detected');
  });

  it('names the collapsed group in the coverage-gap message when the main list is empty', async () => {
    const response: RelatedRulesResponse = {
      id: 'sigma:1',
      related: [],
      same_source: [],
      technique_only: [{
        id: 'elastic:1', title: 'Generic Memory Threat Detected', source: 'elastic', severity: 'medium', language: 'eql',
        quality_score: 60, score: 1, other_vendor: true, reasons: ['technique T1055'],
      }],
    };
    (detectionsApi.related as ReturnType<typeof vi.fn>).mockResolvedValue(response);
    renderPanel();

    await waitFor(() => expect(screen.getByTestId('related-gap')).toBeInTheDocument());
    expect(screen.getByTestId('related-gap')).toHaveTextContent('Rules sharing only its ATT&CK technique are below.');
  });

  it('says nothing else exists when there is no match of any kind', async () => {
    (detectionsApi.related as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'sigma:1', related: [], same_source: [], technique_only: [] });
    renderPanel();

    await waitFor(() => expect(screen.getByTestId('related-gap')).toBeInTheDocument());
    expect(screen.queryByTestId('related-technique-only')).not.toBeInTheDocument();
  });
});
