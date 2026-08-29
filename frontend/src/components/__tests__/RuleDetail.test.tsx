import { describe, it, vi, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { Detection } from '../../types';

vi.mock('../../hooks/useEventIds', () => ({
  useEventIds: () => ({ labels: {}, entries: {} }),
}));

vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({
    techniques: {},
    tactics: {},
    getTacticName: (id: string) => (id === 'TA0002' ? 'Execution' : id),
    getTechniqueName: (id: string) => (id === 'T1059' ? 'Command and Scripting Interpreter' : ''),
    getTacticUrl: (id: string) => `https://attack.mitre.org/tactics/${id}/`,
    getTechniqueUrl: (id: string) => `https://attack.mitre.org/techniques/${id}/`,
  }),
}));

import { RuleDetail } from '../RuleDetail';

const detection = {
  id: 'sigma:abc',
  rule_id: 'abc-123',
  source: 'sigma',
  source_file: 'rules/windows/proc.yml',
  source_rule_url: 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/proc.yml',
  title: 'Suspicious PowerShell Download Cradle',
  description: 'Detects a download cradle.',
  author: 'Test Author',
  severity: 'high',
  status: 'stable',
  language: 'sigma',
  detection_logic: 'selection:\n  CommandLine|contains: IEX',
  raw_content: 'title: Suspicious PowerShell Download Cradle',
  mitre_tactics: ['TA0002'],
  mitre_techniques: ['T1059'],
  mitre_groups: ['G0016'],
  mitre_software: [],
  tags: ['attack.execution', 'attack.t1059'],
  platforms: ['windows'],
  data_sources: ['process_creation'],
  event_types: ['process'],
  references: ['https://example.test/blog'],
  false_positives: ['Admin scripts that download installers'],
  rule_created_date: '2026-01-02T00:00:00Z',
  rule_modified_date: '2026-02-03T00:00:00Z',
  updated_at: '2026-08-29T00:00:00Z',
  quality_details: {
    total: 72,
    dimensions: {
      metadata: { score: 20, of: 20, issues: [] },
      mapping: { score: 10, of: 20, issues: ['no sub-technique'] },
    },
  },
  is_building_block: false,
} as unknown as Detection;

describe('RuleDetail', () => {
  it('renders the normalized view sections and switches to the raw tab', () => {
    const { getByText, getAllByText, queryByText } = render(
      <MemoryRouter><RuleDetail detection={detection} /></MemoryRouter>,
    );
    expect(getByText('Suspicious PowerShell Download Cradle')).toBeInTheDocument();
    // ATT&CK section resolves names through the MITRE context
    expect(getByText('T1059')).toBeInTheDocument();
    expect(getByText(/Command and Scripting Interpreter/)).toBeInTheDocument();
    expect(getByText(/Execution/)).toBeInTheDocument();
    expect(getByText('G0016')).toBeInTheDocument();
    // taxonomy chips + notes + hygiene bars
    expect(getByText('process_creation')).toBeInTheDocument();
    expect(getByText('https://example.test/blog')).toBeInTheDocument();
    expect(getByText(/Admin scripts that download installers/)).toBeInTheDocument();
    expect(getByText('72/100')).toBeInTheDocument();
    expect(getByText('1 issue')).toBeInTheDocument();
    // raw tab replaces the normalized body
    fireEvent.click(getByText('Raw Rule'));
    expect(queryByText('Hygiene Score')).not.toBeInTheDocument();
    expect(getAllByText(/Suspicious PowerShell Download Cradle/).length).toBeGreaterThan(0);
  });
});
