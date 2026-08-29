import { describe, it, vi, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import type { ActorDetail as ActorDetailData, ActorMatchMode } from '../../services/api';

const actor = {
  id: 'G0016',
  kind: 'group',
  name: 'APT29',
  aliases: ['Cozy Bear', 'The Dukes'],
  description: 'A Russian state-sponsored group.',
  references: [],
  mitre_url: 'https://attack.mitre.org/groups/G0016/',
  deprecated: false,
  origin_country: 'RU',
  motivations: ['espionage'],
  target_sectors: ['government'],
  technique_count: 3,
  covered_technique_count: 2,
  gap_count: 1,
  weighted_coverage: 0.6,
  techniques: [
    { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', has_rules: true, rule_count: 40 },
    { technique_id: 'T1003', technique_name: 'OS Credential Dumping', has_rules: true, rule_count: 12 },
    { technique_id: 'T1600', technique_name: 'Weaken Encryption', has_rules: false, rule_count: 0 },
  ],
  coverage_by_source: { sigma: { techniques_covered: 2, rule_count: 50 } },
  associated_software: [{ id: 'S0154', name: 'Cobalt Strike', type: 'tool', has_rules: true, rule_count: 30 }],
  match_counts: { exact: 1, coverage: 52, mention: 4 },
  rules: [
    { id: 'sigma:1', source: 'sigma', severity: 'high', title: 'APT29 Tooling Seen', match_reasons: ['id-tag'], techniques: ['T1059'] },
  ],
} as unknown as ActorDetailData;

const modes: ActorMatchMode[] = [];
vi.mock('../../hooks/useActors', () => ({
  useActor: (_id: string, mode: ActorMatchMode) => {
    modes.push(mode);
    return { data: actor, isLoading: false, error: null };
  },
}));
vi.mock('../../hooks/useAttackRoutes', () => ({ useAttackRouteResolver: () => () => null }));
vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ techniques: {}, tactics: {}, getTechniqueUrl: () => '#', getTacticUrl: () => '#' }),
}));

import { ActorDetail } from '../ActorDetail';

describe('ActorDetail', () => {
  it('renders hero, coverage, techniques, software and rules; match mode drives the query', () => {
    const { getByText, getByTestId, getByRole } = render(
      <MemoryRouter initialEntries={['/actors/G0016']}>
        <Routes><Route path="/actors/:id" element={<ActorDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(getByText('APT29')).toBeInTheDocument();
    expect(getByText(/Cozy Bear/)).toBeInTheDocument();
    expect(getByText('60%')).toBeInTheDocument(); // weighted coverage
    expect(getByTestId('cov-sigma')).toHaveTextContent('2/3');
    expect(getByTestId('cov-splunk')).toHaveTextContent('gap');
    expect(getByText('Weaken Encryption')).toBeInTheDocument();
    expect(getByText('Cobalt Strike')).toBeInTheDocument();
    expect(getByText('APT29 Tooling Seen')).toBeInTheDocument();
    expect(getByText('id-tag')).toBeInTheDocument();

    fireEvent.click(getByRole('radio', { name: /coverage/ }));
    expect(modes[modes.length - 1]).toBe('coverage');
  });
});
