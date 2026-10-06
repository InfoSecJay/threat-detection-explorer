/**
 * DX-17: the catalog row carries the modified date without a ninth
 * column. Domain folds into the Data Source cell as a prefix;
 * Completeness moves to the expanded preview. The Techniques column
 * DX-17 added was removed on 2026-09-17 (Jay): ATT&CK IDs live on the
 * detail page, not in the table.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { Detection } from '../../types';
import { RuleRow } from '../rulelist/RuleRow';

vi.mock('../../hooks/useDetections', () => ({
  useDetection: () => ({ data: undefined, isLoading: false }),
}));

const base = {
  id: 'sigma:1',
  source: 'sigma',
  title: 'Suspicious PowerShell Download Cradle',
  description: '',
  severity: 'high',
  language: 'sigma',
  mitre_techniques: ['T1059.001', 'T1105', 'T1027'],
  domains: ['endpoint'],
  platforms: ['windows'],
  data_sources: ['sysmon'],
  event_types: ['process'],
  rule_created_date: '2026-01-02T00:00:00',
  rule_modified_date: '2026-08-20T00:00:00',
  quality_score: 72,
  rule_modality: 'rule',
} as unknown as Detection;

function renderRow(detection: Detection, expanded = false) {
  return render(
    <MemoryRouter>
      <table><tbody>
        <RuleRow
          detection={detection}
          enableSelection={false}
          selected={false}
          expanded={expanded}
          onToggleSelect={() => {}}
          onToggleExpand={() => {}}
        />
      </tbody></table>
    </MemoryRouter>,
  );
}

describe('RuleRow (DX-17)', () => {
  it('does not render ATT&CK technique IDs in the row', () => {
    renderRow(base);
    expect(screen.queryByTestId('row-techniques')).toBeNull();
    expect(screen.queryByText('T1059.001')).toBeNull();
    expect(screen.queryByText('T1105')).toBeNull();
  });

  it('labels an unpublished severity NOT SPECIFIED, the same word every surface uses (DX-22)', () => {
    renderRow({ ...base, severity: 'unknown' } as unknown as Detection);
    expect(screen.getByText('NOT SPECIFIED')).toHaveAttribute('title', 'The source publishes no severity for this rule');
    expect(screen.queryByText('UNKNOWN')).toBeNull();
  });

  it('has a Modified cell with the exact date on hover', () => {
    renderRow(base);
    const cell = screen.getByTestId('row-modified');
    expect(cell.querySelector('span')).toHaveAttribute('title', expect.stringContaining('Modified'));
    expect(cell.querySelector('span')).toHaveAttribute('title', expect.stringContaining('2026'));
  });

  it('folds the domain into the Data Source cell as a prefix instead of its own column', () => {
    renderRow(base);
    const prefix = screen.getByTestId('row-domain-prefix');
    expect(prefix).toHaveTextContent('endpoint');
    expect(prefix).toHaveAttribute('title', 'Where it applies: endpoint, windows');
    expect(screen.getByTestId('row-data-sources')).toHaveTextContent('sysmon');
  });

  it('keeps Completeness out of the row and puts it in the expanded preview', () => {
    renderRow(base, true);
    // The row itself no longer carries the score as its own cell...
    const rows = screen.getAllByRole('row');
    expect(rows[0]).not.toHaveTextContent('72');
    // ...the expanded preview does.
    expect(screen.getByTestId('preview-completeness')).toHaveTextContent('72');
  });
});

describe('RuleRow content: snippet (DX-12 / #167)', () => {
  const snippet = {
    term: 'citrix',
    before: '...and not process.code_signature.subject_name : "',
    match: 'Citrix',
    after: ' Systems, Inc."',
    field: 'detection_logic',
    negated: true,
  };

  it('shows the match in context and flags an exclusion-only hit', () => {
    renderRow({ ...base, content_snippet: snippet } as unknown as Detection);
    const row = screen.getByTestId('row-snippet');
    expect(row).toHaveTextContent('subject_name : "Citrix Systems, Inc."');
    expect(row.querySelector('mark')).toHaveTextContent('Citrix');
    expect(screen.getByTestId('row-snippet-negated')).toHaveTextContent('excluded');
  });

  it('shows no flag for a plain hit and nothing without a snippet', () => {
    renderRow({ ...base, content_snippet: { ...snippet, negated: false } } as unknown as Detection);
    expect(screen.getByTestId('row-snippet')).toBeInTheDocument();
    expect(screen.queryByTestId('row-snippet-negated')).toBeNull();
    screen.getByTestId('row-snippet').remove();
    renderRow(base);
    expect(screen.queryByTestId('row-snippet')).toBeNull();
  });
});
