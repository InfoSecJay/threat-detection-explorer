/**
 * useEventIds indexes the dictionary by both the namespaced key the API
 * returns ("security:4688", #110) and the bare number, so chips and
 * facets label either form of a stored value.
 */
import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

vi.mock('../../services/api', () => ({
  queryApi: {
    getEventIds: vi.fn().mockResolvedValue({
      event_ids: {
        'security:4688': { event_id: '4688', label: 'Process created', provider: 'windows_security', channel: 'Security', event_types: ['process_creation'] },
        'sysmon:1': { event_id: '1', label: 'Process creation', provider: 'sysmon', channel: 'Microsoft-Windows-Sysmon/Operational', event_types: ['process_creation'] },
      },
    }),
  },
}));

import { useEventIds } from '../useEventIds';

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe('useEventIds', () => {
  it('labels namespaced and bare ids alike', async () => {
    const { result } = renderHook(() => useEventIds(), { wrapper });
    await waitFor(() => expect(Object.keys(result.current.labels).length).toBeGreaterThan(0));
    expect(result.current.labels['security:4688']).toBe('Process created');
    expect(result.current.labels['4688']).toBe('Process created');
    expect(result.current.labels['sysmon:1']).toBe('Process creation');
    expect(result.current.entries['1'].channel).toContain('Sysmon');
    // A namespaced id the dictionary does not know stays unlabelled.
    expect(result.current.labels['security:1']).toBeUndefined();
  });
});
