/**
 * Baked headline counts (#82 S2.7): with the live queries still
 * pending, the stats strip and the MITRE showcase card show the numbers
 * baked at build time rather than dashes / "loading". Once live data
 * exists it wins.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../../constants/snapshot', () => ({
  BAKED_SNAPSHOT: {
    rules: 15588,
    coverage: { covered: 186, total: 207, percent: 89.9 },
    last_sync: '2026-09-01T07:51:01Z',
    baked_at: '2026-09-01T12:00:00Z',
  },
}));

const pending = { data: undefined, isLoading: true, error: null };
const live = {
  statistics: undefined as undefined | { total: number },
  coverage: undefined as undefined | { summary: { techniques_with_any_coverage: number; total_techniques: number; overall_coverage_percent: number } },
};
vi.mock('../../hooks/useDetections', () => ({ useStatistics: () => (live.statistics ? { data: live.statistics } : pending) }));
vi.mock('../../hooks/useCompare', () => ({ useCoverageMatrix: () => (live.coverage ? { data: live.coverage } : pending) }));
vi.mock('../../hooks/useRepositories', () => ({ useRepositories: () => pending }));
vi.mock('../../hooks/useActors', () => ({ useActorsQuery: () => pending }));
vi.mock('../../hooks/useTrending', () => ({ useSourceDeltas: () => pending }));

import { StatsStrip } from '../home/StatsStrip';
import { ShowcaseCards } from '../home/ShowcaseCards';

describe('baked snapshot bridges the first paint', () => {
  it('shows baked numbers while every query is pending', () => {
    render(<MemoryRouter><StatsStrip /><ShowcaseCards /></MemoryRouter>);
    expect(screen.getByTestId('stat-rules')).toHaveTextContent('15,588');
    expect(screen.getByTestId('stat-coverage')).toHaveTextContent('186 / 207');
    expect(screen.getByTestId('stat-sync')).not.toHaveTextContent('—');
    expect(screen.getByTestId('card-mitre-fact')).toHaveTextContent('89.9%');
    expect(screen.getByTestId('card-mitre-fact')).toHaveTextContent('186 / 207');
  });

  it('live data replaces the baked numbers', () => {
    live.statistics = { total: 15610 };
    live.coverage = { summary: { techniques_with_any_coverage: 188, total_techniques: 207, overall_coverage_percent: 90.8 } };
    render(<MemoryRouter><StatsStrip /><ShowcaseCards /></MemoryRouter>);
    expect(screen.getByTestId('stat-rules')).toHaveTextContent('15,610');
    expect(screen.getByTestId('stat-coverage')).toHaveTextContent('188 / 207');
    expect(screen.getByTestId('card-mitre-fact')).toHaveTextContent('90.8%');
  });
});
