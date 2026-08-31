import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Methodology } from '../Methodology';

vi.mock('../../services/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../services/api')>();
  return {
    ...actual,
    methodologyApi: {
      get: vi.fn(async () => ({
        generated_at: '2026-08-31T00:00:00Z',
        principles: ['Every file our discovery globs match on the pinned commit is parsed.'],
        sources: [{
          name: 'sigma', url: 'https://github.com/SigmaHQ/sigma.git', branch: 'master',
          sparse_checkout: null, include_patterns: ['rules/**/*.yml'],
          exclude_dirs: ['.git', 'deprecated'], scope_notes: 'Deprecated excluded.',
          last_commit_hash: 'da9bb07d642a', last_sync_at: '2026-08-30T19:50:43Z', rule_count: 3760,
        }],
      })),
    },
  };
});

describe('Methodology page', () => {
  it('renders the count table, principles and licensing at its own URL', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/methodology']}>
          <Methodology />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByTestId('methodology-page')).toBeInTheDocument();
    expect(document.title).toContain('Methodology');
    // Wait on query-driven content, not the static header.
    await waitFor(() => expect(screen.getByText('SigmaHQ/sigma')).toBeInTheDocument());
    expect(screen.getByText('What We Count')).toBeInTheDocument();
    expect(screen.getByText(/Apache-2.0/)).toBeInTheDocument();
    expect(screen.getByText('Metadata completeness score')).toBeInTheDocument();
  });
});
