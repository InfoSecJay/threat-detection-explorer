/**
 * Render test for the hero coverage constellation: cells match the
 * technique list, coverage and gaps are distinguishable, the whole
 * thing links to /mitre, and empty data renders nothing.
 */

import { describe, it, vi, expect, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { CoverageMatrixResponse } from '../../services/api';

const fixture: CoverageMatrixResponse = {
  sources: ['sigma', 'splunk'],
  tactics: [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      short_name: 'reconnaissance',
      technique_count: 3,
      techniques: [
        { id: 'T1595', name: 'Active Scanning', is_subtechnique: false, coverage: { sigma: 2 }, total_detections: 2, sources_with_coverage: 1 },
        { id: 'T1592', name: 'Gather Victim Host Information', is_subtechnique: false, coverage: {}, total_detections: 0, sources_with_coverage: 0 },
        { id: 'T1589', name: 'Gather Victim Identity Information', is_subtechnique: false, coverage: { sigma: 30 }, total_detections: 30, sources_with_coverage: 1 },
      ],
    },
    {
      id: 'TA0040',
      name: 'Impact',
      short_name: 'impact',
      technique_count: 1,
      techniques: [
        { id: 'T1486', name: 'Data Encrypted for Impact', is_subtechnique: false, coverage: { sigma: 5, splunk: 3 }, total_detections: 8, sources_with_coverage: 2 },
      ],
    },
  ],
  summary: {
    total_tactics: 2,
    total_techniques: 4,
    techniques_with_any_coverage: 3,
    overall_coverage_percent: 75,
    source_coverage: {},
  },
};

let matrixData: CoverageMatrixResponse | undefined = fixture;

vi.mock('../../hooks/useCompare', () => ({
  useCoverageMatrix: () => ({ data: matrixData, isLoading: false, error: null }),
}));

import { CoverageConstellation } from '../home/CoverageConstellation';

function renderConstellation() {
  return render(
    <MemoryRouter>
      <CoverageConstellation />
    </MemoryRouter>,
  );
}

afterEach(() => {
  matrixData = fixture;
});

describe('CoverageConstellation', () => {
  it('draws one cell per technique and separates coverage from gaps', () => {
    const { container, getByTestId } = renderConstellation();
    expect(container.querySelectorAll('[data-cell]')).toHaveLength(4);
    expect(container.querySelectorAll('[data-cell="covered"]')).toHaveLength(3);
    expect(container.querySelectorAll('[data-cell="gap"]')).toHaveLength(1);
    expect(getByTestId('hero-constellation')).toHaveAttribute('href', '/mitre');
    expect(getByTestId('hero-constellation')).toHaveAttribute(
      'aria-label',
      'ATT&CK Enterprise coverage: 3 of 4 techniques covered. Open the coverage browser.',
    );
  });

  it('renders nothing while the matrix has not loaded', () => {
    matrixData = undefined;
    const { container } = renderConstellation();
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when the matrix has no tactics', () => {
    matrixData = { ...fixture, tactics: [] };
    const { container } = renderConstellation();
    expect(container).toBeEmptyDOMElement();
  });
});
