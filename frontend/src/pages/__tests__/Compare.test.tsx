import { describe, it, vi, expect } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { CompareDiffResponse } from '../../services/api';

const DIFF: CompareDiffResponse = {
  rules: [
    { id: 'a', title: 'Rundll32 JS Sigma', source: 'sigma', severity: 'high', status: 'stable', language: 'sigma', rule_modality: 'rule', platforms: ['windows'], data_sources: ['sysmon'], event_types: ['process_creation'], mitre_tactics: ['TA0005'], mitre_techniques: ['T1218.011'], quality_score: 70, query_complexity: 'moderate', source_rule_url: null, observable_count: 3 },
    { id: 'b', title: 'Rundll32 JS Elastic', source: 'elastic', severity: 'medium', status: 'stable', language: 'eql', rule_modality: 'rule', platforms: ['windows'], data_sources: ['elastic_endpoint'], event_types: ['process_creation'], mitre_tactics: ['TA0005'], mitre_techniques: ['T1218.011'], quality_score: null, query_complexity: 'simple', source_rule_url: null, observable_count: 2 },
  ],
  observables: [
    { type: 'process', subtype: 'process_name', value: 'rundll32.exe', present_in: ['a', 'b'], negated_in: [], fields: { a: ['Image'], b: ['process.name'] }, shared: true },
    { type: 'process', subtype: 'parent_process_name', value: 'explorer.exe', present_in: ['a', 'b'], negated_in: ['b'], fields: { a: ['ParentImage'], b: ['process.parent.name'] }, shared: true },
    { type: 'process', subtype: 'command_line_pattern', value: 'javascript:', present_in: ['a'], negated_in: [], fields: { a: ['CommandLine'] }, shared: false },
  ],
  axes: {
    mitre_techniques: [{ value: 'T1218.011', present_in: ['a', 'b'] }],
    mitre_tactics: [{ value: 'TA0005', present_in: ['a', 'b'] }],
    data_sources: [{ value: 'sysmon', present_in: ['a'] }, { value: 'elastic_endpoint', present_in: ['b'] }],
    platforms: [{ value: 'windows', present_in: ['a', 'b'] }],
    event_types: [{ value: 'process_creation', present_in: ['a', 'b'] }],
    source_tables: [],
    fields: [{ value: 'Image', present_in: ['a'] }],
  },
  summary: {
    rules: 2, observables: 3, shared_by_all: 2, unique_by_rule: { a: 1, b: 0 }, shared_techniques: ['T1218.011'],
    contradictions: [{ type: 'process', subtype: 'parent_process_name', value: 'explorer.exe', matched_in: ['a'], excluded_in: ['b'] }],
  },
  missing_ids: ['ghost'],
};

vi.mock('../../hooks/useCompare', () => ({
  useCompareDiff: (ids: string[]) => (ids.length >= 2 ? { data: DIFF, isLoading: false, error: null } : { data: undefined, isLoading: false, error: null }),
}));
vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ getTechniqueName: (id: string) => (id === 'T1218.011' ? 'Rundll32' : id), getTacticName: (id: string) => id, tactics: {}, techniques: {}, isLoading: false, error: null, getTacticUrl: () => '', getTechniqueUrl: () => '', refresh: async () => {} }),
}));

import { Compare } from '../Compare';
import { diffToMarkdown } from '../../utils/compareMarkdown';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path="/compare" element={<Compare />} /></Routes>
    </MemoryRouter>,
  );
}

describe('Compare', () => {
  it('explains how to pick rules when fewer than two ids are given', () => {
    const { getByTestId } = renderAt('/compare');
    expect(getByTestId('compare-landing')).toHaveTextContent('Pick two to six rules');
  });

  it('renders the observable matrix with each vendor field, exclusions and the verdict line', async () => {
    const { getByTestId, queryByTestId } = renderAt('/compare?ids=a,b,ghost');
    await waitFor(() => expect(getByTestId('compare-page')).toBeInTheDocument());
    expect(getByTestId('compare-rule-a')).toHaveTextContent('Rundll32 JS Sigma');
    expect(getByTestId('compare-rule-a')).toHaveTextContent('1 unique');
    expect(getByTestId('compare-missing')).toHaveTextContent('1 id not found');
    const row = getByTestId('diff-row-rundll32.exe');
    expect(row).toHaveTextContent('Image');
    expect(row).toHaveTextContent('process.name');
    expect(getByTestId('diff-row-explorer.exe')).toHaveTextContent('NOT');
    expect(getByTestId('compare-summary')).toHaveTextContent('3 distinct observables, 2 shared by every rule');
    expect(getByTestId('compare-summary')).toHaveTextContent('T1218.011');
    expect(getByTestId('compare-contradictions')).toHaveTextContent('explorer.exe is matched by R1 but excluded by R2');
    expect(getByTestId('diff-axis-mitre_techniques')).toHaveTextContent('Rundll32');
    // Differences view hides what every rule shares, in both tables.
    fireEvent.click(getByTestId('view-differences'));
    expect(queryByTestId('diff-row-rundll32.exe')).toBeNull();
    expect(getByTestId('diff-row-javascript:')).toBeInTheDocument();
    expect(queryByTestId('diff-axis-mitre_techniques')).toBeNull();
    expect(getByTestId('diff-axis-data_sources')).toHaveTextContent('elastic_endpoint');
    fireEvent.click(getByTestId('view-shared'));
    expect(queryByTestId('diff-row-javascript:')).toBeNull();
  });

  it('exports the same matrix as Markdown with marks and vendor fields', () => {
    const md = diffToMarkdown(DIFF, 'http://localhost:3000', (s) => s.toUpperCase());
    expect(md).toContain('[Rundll32 JS Sigma](http://localhost:3000/detections/a) — SIGMA · high · sigma · completeness 70');
    expect(md).toContain('3 observables, 2 shared by all; unique: R1 1, R2 0');
    expect(md).toContain('| process/process_name `rundll32.exe` | x `Image` | x `process.name` |');
    expect(md).toContain('| process/parent_process_name `explorer.exe` | x `ParentImage` | NOT `process.parent.name` |');
    expect(md).toContain('| process/command_line_pattern `javascript:` | x `CommandLine` | - |');
    expect(md).toContain('`explorer.exe` (process/parent_process_name): matched in R1, excluded in R2');
    expect(md).toContain('| [T1218.011](http://localhost:3000/mitre/T1218.011) | x | x |');
    expect(md).not.toMatch(/## Source tables/); // empty axes are skipped
    expect(md).toContain('/compare?ids=a,b');
  });
});
