import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, renderHook, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NotFound } from '../pages/NotFound';
import { RelatedRules } from '../components/ruledetail/RelatedRules';
import { DataSourceHeatmap } from '../pages/mitre/DataSourceHeatmap';
import { useDocumentMeta } from '../hooks/useDocumentMeta';

vi.mock('../services/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/api')>();
  return {
    ...actual,
    detectionsApi: {
      ...actual.detectionsApi,
      related: vi.fn(async () => ({
        id: 'sigma:a',
        related: [
          { id: 'splunk:b', title: 'Mimikatz LSASS', source: 'splunk', severity: 'high', language: 'spl', quality_score: 80, score: 5, reasons: ['technique T1003', 'process mimikatz.exe'], other_vendor: true },
          { id: 'sigma:c', title: 'cmd only', source: 'sigma', severity: 'low', language: 'sigma', quality_score: 60, score: 2, reasons: ['technique T1059'], other_vendor: false },
        ],
      })),
    },
    mitreApi: {
      ...actual.mitreApi,
      coverageByDataSource: vi.fn(async () => ({
        data_sources: [{ id: 'sysmon', rules: 20 }, { id: 'aws_cloudtrail', rules: 5 }],
        rows: [{ technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution', rules: 12, by_data_source: { sysmon: 10 } }],
        total_techniques: 300,
      })),
    },
  };
});

function wrap(ui: React.ReactNode, path = '/') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="*" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('easy wins', () => {
  beforeEach(() => {
    document.title = 'Threat Detection Explorer';
  });

  it('404 page names the path and links back into the catalog', () => {
    wrap(<NotFound />, '/no/such/page');
    expect(screen.getByTestId('not-found')).toHaveTextContent('/no/such/page');
    expect(screen.getByRole('link', { name: /search the catalog/i })).toHaveAttribute('href', '/detections');
    expect(document.title).toContain('Not found');
  });

  it('related rules card lists other vendors first with the shared reasons', async () => {
    wrap(<RelatedRules id="sigma:a" source="sigma" />);
    await waitFor(() => expect(screen.getByTestId('related-splunk:b')).toBeInTheDocument());
    const items = screen.getAllByTestId(/^related-/);
    expect(items[0]).toHaveTextContent('Mimikatz LSASS');
    expect(items[0]).toHaveTextContent('process mimikatz.exe');
    expect(screen.getByText(/2 rules/)).toHaveTextContent('1 other source');
    expect(screen.getByRole('link', { name: 'cmd only' })).toHaveAttribute('href', '/detections/sigma:c');
  });

  it('data-source heatmap renders one column per source and drills to filtered rules', async () => {
    wrap(<DataSourceHeatmap />, '/mitre/heatmap');
    await waitFor(() => expect(screen.getByTestId('ds-T1059')).toBeInTheDocument());
    expect(screen.getByText('sysmon')).toBeInTheDocument();
    expect(screen.getByText('aws_cloudtrail')).toBeInTheDocument();
    const cell = screen.getByRole('link', { name: '10' });
    expect(cell).toHaveAttribute('href', '/detections?mitre_techniques=T1059&data_sources_normalized=sysmon');
    expect(screen.getByTestId('ds-T1059')).toHaveTextContent('Execution');
    expect(document.title).toContain('Coverage by data source');
  });

  it('useDocumentMeta sets title + description and restores on unmount', () => {
    const meta = document.createElement('meta');
    meta.name = 'description';
    meta.content = 'default';
    document.head.appendChild(meta);
    const { unmount } = renderHook(() => useDocumentMeta('APT29 (G0016)', 'A group.'));
    expect(document.title).toBe('APT29 (G0016) · Threat Detection Explorer');
    expect(meta.content).toBe('A group.');
    unmount();
    expect(document.title).toBe('Threat Detection Explorer');
    expect(meta.content).toBe('default');
    meta.remove();
  });
});
