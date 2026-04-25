/**
 * Render-smoke for the Comparison page.
 *
 * Three query modes (keyword / technique / platform) drive the same
 * results pane. The page renders without an active query — that's the
 * landing state we cover here.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../hooks/useCompare', () => ({
  // No active query → useCompare's `enabled` flag is false; useQuery
  // returns the idle shape (data: undefined, isLoading: false).
  useCompare: () => ({ data: undefined, isLoading: false, error: null }),
}));

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

import { Compare } from '../Compare';

function renderPage(initialUrl = '/compare') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialUrl]}>
        <Compare />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Compare', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the landing state without crashing', async () => {
    const { findByText } = renderPage();
    // Page header copy is unique enough to anchor on. Reaching this
    // assertion means the page mounted without throwing.
    expect(await findByText(/Cross-Vendor Comparison/i)).toBeInTheDocument();
  });

  it('seeds query mode + value from URL params', async () => {
    const { findByDisplayValue } = renderPage('/compare?keyword=powershell');
    // The query input should be pre-populated from the URL — proves
    // the URL-state seed code path runs without throwing.
    expect(await findByDisplayValue('powershell')).toBeInTheDocument();
  });
});
