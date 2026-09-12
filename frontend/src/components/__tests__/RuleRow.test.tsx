/**
 * DX-17: the catalog row carries the two things detection engineers
 * triage on -- ATT&CK techniques and the modified date -- without a
 * ninth column. Domain folds into the Data Source cell as a prefix;
 * Completeness moves to the expanded preview.
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
  it('shows the first two techniques as /mitre links plus a +n overflow chip', () => {
    renderRow(base);
    const cell = screen.getByTestId('row-techniques');
    const links = cell.querySelectorAll('a');
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute('href', '/mitre/T1059.001');
    expect(links[1]).toHaveAttribute('href', '/mitre/T1105');
    expect(cell).toHaveTextContent('+1');
    expect(cell.querySelector('[title="T1027"]')).not.toBeNull();
  });

  it('labels an unpublished severity NOT SPECIFIED, the same word every surface uses (DX-22)', () => {
    renderRow({ ...base, severity: 'unknown' } as unknown as Detection);
    expect(screen.getByText('NOT SPECIFIED')).toHaveAttribute('title', 'The source publishes no severity for this rule');
    expect(screen.queryByText('UNKNOWN')).toBeNull();
  });

  it('renders a dash when a rule has no ATT&CK mapping', () => {
    renderRow({ ...base, mitre_techniques: [] } as unknown as Detection);
    expect(screen.getByTestId('row-techniques')).toHaveTextContent('-');
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
