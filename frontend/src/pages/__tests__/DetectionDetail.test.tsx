/**
 * DX-19 / #161: what a rule URL renders when the rule is not there.
 * A tombstoned rule (410) gets its preserved record with a link to the
 * last indexed file at its pinned commit; an id that never existed
 * (404) gets a real not-found page, never the raw client error.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

const state: { data?: unknown; error?: unknown } = {};
vi.mock('../../hooks/useDetections', () => ({
  useDetection: () => ({ data: state.data, error: state.error, isLoading: false }),
  useEventTypeParents: () => ({}),
}));
vi.mock('../../hooks/useEventIds', () => ({ useEventIds: () => ({ labels: {}, entries: {} }) }));
vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ techniques: {}, tactics: {}, getTacticName: (id: string) => id, getTechniqueName: () => '', getTacticUrl: () => '#', getTechniqueUrl: () => '#' }),
}));

import { DetectionDetail } from '../DetectionDetail';

function renderAt(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/detections/${id}`]}>
      <Routes><Route path="/detections/:id" element={<DetectionDetail />} /></Routes>
    </MemoryRouter>,
  );
}

const SHA = 'ffc8ad66' + '0'.repeat(32);

describe('DetectionDetail when the rule is not there', () => {
  afterEach(() => {
    state.data = undefined;
    state.error = undefined;
    document.head.querySelectorAll('meta[name="robots"]').forEach((m) => m.remove());
  });

  it('renders a not-found page with noindex for an id that never existed (404)', () => {
    state.error = Object.assign(new Error('Request failed with status code 404'), { response: { status: 404, data: { detail: 'Detection not found' } } });
    renderAt('00000000-0000-5000-8000-000000000000');
    expect(screen.getByTestId('rule-not-found')).toHaveTextContent('No rule with this id');
    expect(screen.getByTestId('rule-not-found')).toHaveTextContent('00000000-0000-5000-8000-000000000000');
    expect(screen.queryByText(/Request failed with status code/)).toBeNull();
    expect(document.head.querySelector('meta[name="robots"]')).toHaveAttribute('content', 'noindex');
    expect(screen.getByRole('link', { name: /search the catalog/i })).toHaveAttribute('href', '/detections');
  });

  it('renders the tombstone with a link to the last indexed file at its pinned commit (410)', () => {
    state.error = Object.assign(new Error('Request failed with status code 410'), {
      response: {
        status: 410,
        data: {
          removed: true, id: 'sigma:gone', rule_id: null, source: 'sigma', source_file: 'rules/gone.yml',
          title: 'Rule That Left', severity: 'high', mitre_techniques: ['T1059'],
          first_seen_at: '2026-01-01T00:00:00Z', removed_at: '2026-09-01T00:00:00Z',
          last_seen: { source_rule_url: `https://github.com/SigmaHQ/sigma/blob/${SHA}/rules/gone.yml`, upstream_history: [] },
          successors: [],
        },
      },
    });
    renderAt('sigma:gone');
    expect(screen.getByTestId('tombstone')).toHaveTextContent('Rule That Left');
    const link = screen.getByTestId('tombstone-upstream');
    expect(link).toHaveAttribute('href', `https://github.com/SigmaHQ/sigma/blob/${SHA}/rules/gone.yml`);
    expect(link).toHaveTextContent('commit ffc8ad6');
  });

  it('offers no upstream link on a tombstone whose last link was a branch (would 404 on GitHub)', () => {
    state.error = Object.assign(new Error('410'), {
      response: {
        status: 410,
        data: {
          removed: true, id: 'sigma:old', rule_id: null, source: 'sigma', source_file: 'rules/old.yml',
          title: 'Old Tombstone', severity: null, mitre_techniques: [], first_seen_at: null, removed_at: null,
          last_seen: { source_rule_url: 'https://github.com/SigmaHQ/sigma/blob/master/rules/old.yml' }, successors: [],
        },
      },
    });
    renderAt('sigma:old');
    expect(screen.getByTestId('tombstone')).toBeInTheDocument();
    expect(screen.queryByTestId('tombstone-upstream')).toBeNull();
  });

  it('shows a plain load error, with a way back, for anything that is not a 404 or 410', () => {
    state.error = Object.assign(new Error('Network Error'), { response: { status: 502 } });
    renderAt('sigma:abc');
    expect(screen.getByTestId('rule-load-error')).toHaveTextContent('could not be loaded (HTTP 502)');
    expect(screen.getByRole('link', { name: /go back to the catalog/i })).toHaveAttribute('href', '/detections');
  });
});
