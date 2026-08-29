import type { useCoverageMatrix } from '../../hooks/useCompare';

/** The loaded /mitre/coverage-matrix payload, as the panes consume it. */
export type CoverageData = NonNullable<ReturnType<typeof useCoverageMatrix>['data']>;

export type CoverageFilter = 'all' | 'covered' | 'gaps';
