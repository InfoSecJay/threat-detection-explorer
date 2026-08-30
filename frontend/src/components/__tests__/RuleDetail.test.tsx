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

vi.mock('../ruledetail/RelatedRules', () => ({
  RelatedRules: () => <div data-testid="related-rules" />,
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
      mitre: { score: 17, of: 20, issues: ['no sub-technique precision'] },
      specificity: { score: 15, of: 20, issues: [] },
      documentation: { score: 12, of: 20, issues: ['no investigation guidance'] },
      testability: { score: 8, of: 20, issues: ['no Atomic Red Team reference', 'no embedded test cases'] },
    },
  },
  is_building_block: false,
} as unknown as Detection;

describe('RuleDetail', () => {
  it('lays out About (left) and Definition (right) with the query and required fields', () => {
    const { getByText, getByTestId } = render(
      <MemoryRouter><RuleDetail detection={detection} /></MemoryRouter>,
    );
    expect(getByText('Suspicious PowerShell Download Cradle')).toBeInTheDocument();
    expect(getByTestId('rule-byline')).toHaveTextContent('Created by Test Author');
    // About: ATT&CK resolves names through the MITRE context, references, FPs
    expect(getByTestId('about-card')).toHaveTextContent('T1059');
    expect(getByTestId('about-card')).toHaveTextContent('Command and Scripting Interpreter');
    expect(getByTestId('about-card')).toHaveTextContent('G0016');
    expect(getByTestId('about-card')).toHaveTextContent('https://example.test/blog');
    expect(getByTestId('about-card')).toHaveTextContent('Admin scripts that download installers');
    // Definition: where it reads from, the query, the fields it tests
    expect(getByTestId('definition-card')).toHaveTextContent('process_creation');
    expect(getByTestId('definition-card')).toHaveTextContent('windows');
    expect(getByTestId('def-query')).toHaveTextContent('CommandLine|contains: IEX');
  });

  it('explains the hygiene score check by check and aligns issue-free rows', () => {
    const { getByTestId, queryByTestId } = render(
      <MemoryRouter><RuleDetail detection={detection} /></MemoryRouter>,
    );
    expect(getByTestId('hygiene')).toHaveTextContent('72/100');
    expect(getByTestId('hygiene-metadata')).toHaveTextContent('complete'); // no issues -> still a chip in the column
    expect(getByTestId('hygiene-mitre')).toHaveTextContent('1 issue');
    expect(getByTestId('hygiene-testability')).toHaveTextContent('2 issues');
    expect(queryByTestId('hygiene-rubric')).not.toBeInTheDocument();
    fireEvent.click(getByTestId('hygiene-explain'));
    expect(getByTestId('hygiene-rubric')).toHaveTextContent('worth 20 points');
    expect(getByTestId('hygiene-rubric')).toHaveTextContent('Atomic Red Team reference');
  });

  it('toggles the definition to the raw upstream source', () => {
    const { getByTestId, queryByTestId } = render(
      <MemoryRouter><RuleDetail detection={detection} /></MemoryRouter>,
    );
    expect(queryByTestId('raw-source')).not.toBeInTheDocument();
    fireEvent.click(getByTestId('view-source'));
    expect(getByTestId('raw-source')).toHaveTextContent('title: Suspicious PowerShell Download Cradle');
    expect(queryByTestId('def-query')).not.toBeInTheDocument();
    expect(getByTestId('view-source')).toHaveTextContent('View definition');
    // About stays put while viewing source
    expect(getByTestId('hygiene')).toBeInTheDocument();
  });

  it('offers an investigation-guide tab as the slot for generated guides', () => {
    const { getByRole, getByTestId } = render(
      <MemoryRouter><RuleDetail detection={detection} /></MemoryRouter>,
    );
    fireEvent.click(getByRole('tab', { name: 'Investigation guide' }));
    expect(getByTestId('guide-placeholder')).toHaveTextContent('No investigation guide for this rule');
  });

  it('renders a vendor-authored investigation guide as markdown when present', () => {
    const guided = { ...detection, investigation_guide: ['## Triage steps', '', '- Check `event.action`', '- Review the **user**'].join('\n') } as unknown as Detection;
    const { getByRole, getByTestId, queryByTestId } = render(
      <MemoryRouter><RuleDetail detection={guided} /></MemoryRouter>,
    );
    fireEvent.click(getByRole('tab', { name: 'Investigation guide' }));
    expect(queryByTestId('guide-placeholder')).not.toBeInTheDocument();
    expect(getByTestId('guide-markdown')).toHaveTextContent('Triage steps');
    expect(getByTestId('guide-markdown').querySelector('h2')).not.toBeNull();
    expect(getByTestId('guide-markdown').querySelectorAll('li')).toHaveLength(2);
  });
});
