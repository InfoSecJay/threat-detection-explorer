/**
 * Render-smoke for the Detections page.
 *
 * The page does the most state juggling on the site: URL ↔ filter
 * state two-way sync, mobile drawer toggle, export modal, search
 * submit. Most foot-guns here are useEffect dep mistakes that cause
 * either render loops or stale URLs. A render-smoke catches the loop
 * class; functional tests for the URL sync would be a separate file.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../hooks/useDetections', () => ({
  useDetections: () => ({
    data: { items: [], total: 0, offset: 0, limit: 25 },
    isLoading: false,
    error: null,
  }),
  useFilterOptions: () => ({
    data: {
      sources: ['sigma', 'splunk'],
      statuses: ['stable'],
      severities: ['high'],
      languages: ['sigma'],
      platforms: [{ value: 'windows', count: 100 }],
      data_sources: [],
      event_types: [],
    },
  }),
  // ExportModal is mounted (with isOpen=false) via DetectionList. Even
  // though it returns null when closed, useMutation gets called during
  // hook init and needs a non-null mutation handle.
  useExport: () => ({
    mutate: () => {},
    mutateAsync: async () => {},
    isPending: false,
    isError: false,
    error: null,
    reset: () => {},
  }),
}));

// Same closure-stability fix as MitreCoverage.test.tsx — the
// FilterPanel reads useMitre() and rebuilds its tactic options via
// useMemo([tactics]). A fresh `tactics` reference per render breaks
// memoization but doesn't cause an infinite loop here. Still, keep
// the pattern consistent for safety.
vi.mock('../../contexts/MitreContext', () => {
  const VALUE = {
    tactics: {},
    techniques: {},
    isLoading: false,
    error: null,
    getTacticName: (id: string) => id,
    getTechniqueName: (id: string) => id,
    getTacticUrl: () => '',
    getTechniqueUrl: () => '',
    refresh: async () => {},
  };
  return { useMitre: () => VALUE };
});

import { DetectionList } from '../DetectionList';

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/detections']}>
        <DetectionList />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('DetectionList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing on the empty-corpus path', async () => {
    const { findByText } = renderPage();
    // The empty-state message comes from RuleList. Its presence proves
    // the whole page chain mounted: DetectionList → FilterPanel →
    // RuleList without throwing.
    expect(await findByText(/no detections found/i)).toBeInTheDocument();
  });
});
