/**
 * Render-smoke test for the MITRE browser page.
 *
 * Same shape as IndustryIntel.test.tsx — mock every data hook,
 * mount under MemoryRouter + QueryClientProvider, assert the page
 * renders without throwing for both the no-selection (summary)
 * and selected-technique (detail) routes.
 *
 * MitreCoverage is the second-most-complex page after IndustryIntel
 * and was rewritten last week. The page reads `useParams()` for
 * `:techniqueId`, so we exercise both URL shapes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// Stub the coverage matrix endpoint with a minimal but realistic shape
// covering one tactic + one parent technique + one sub-technique.
const COVERAGE_FIXTURE = {
  sources: ['sigma', 'splunk'],
  tactics: [
    {
      id: 'TA0002',
      name: 'Execution',
      short_name: 'execution',
      technique_count: 2,
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          is_subtechnique: false,
          coverage: { sigma: 5, splunk: 3 },
          total_detections: 8,
          sources_with_coverage: 2,
        },
        {
          id: 'T1059.001',
          name: 'PowerShell',
          is_subtechnique: true,
          coverage: { sigma: 2 },
          total_detections: 2,
          sources_with_coverage: 1,
        },
      ],
    },
  ],
  summary: {
    total_tactics: 1,
    total_techniques: 2,
    techniques_with_any_coverage: 2,
    overall_coverage_percent: 100,
    source_coverage: {
      sigma: { covered_techniques: 2, total_techniques: 2, coverage_percent: 100 },
      splunk: { covered_techniques: 1, total_techniques: 2, coverage_percent: 50 },
    },
    unmapped_techniques: [],
  },
};

vi.mock('../../hooks/useCompare', () => ({
  useCoverageMatrix: () => ({ data: COVERAGE_FIXTURE, isLoading: false, error: null }),
}));

vi.mock('../../hooks/useDetections', () => ({
  useDetections: () => ({
    data: {
      items: [
        {
          id: 'rule-1',
          source: 'sigma',
          source_file: 'sigma/rule1.yml',
          source_repo_url: '',
          source_rule_url: null,
          rule_id: null,
          title: 'PowerShell encoded command',
          description: '',
          author: null,
          status: 'stable',
          severity: 'high',
          platforms: ['windows'],
          data_sources: ['sysmon'],
          event_types: ['process_creation'],
          mitre_tactics: ['TA0002'],
          mitre_techniques: ['T1059.001'],
          detection_logic: '',
          language: 'sigma',
          tags: [],
          references: [],
          false_positives: [],
          extracted_fields_used: [],
          extracted_event_ids: [],
          extracted_process_names: [],
          extracted_file_paths: [],
          extracted_registry_keys: [],
          extracted_network_indicators: [],
          extracted_source_tables: [],
          extracted_observables: [],
          query_complexity: 'simple',
          extracted_api_actions: [],
          extracted_target_resources: [],
          rule_created_date: null,
          rule_modified_date: null,
          created_at: '2026-04-01T00:00:00Z',
          updated_at: '2026-04-01T00:00:00Z',
        },
      ],
      total: 1,
      offset: 0,
      limit: 200,
    },
    isLoading: false,
  }),
}));

// CRITICAL: useMitre must return the SAME object reference on every
// call. The page has a `useEffect([selectedId, techniques])` that
// auto-expands parent tactics; if this object changes identity on each
// render, the effect re-fires forever and the test hangs indefinitely
// (vitest worker timeout). Building the value inside the factory
// closure (which `vi.mock` evaluates ONCE at module init) gives a
// stable reference.
vi.mock('../../contexts/MitreContext', () => {
  const MITRE_VALUE = {
    tactics: {
      TA0002: {
        id: 'TA0002', name: 'Execution', short_name: 'execution',
        url: 'https://attack.mitre.org/tactics/TA0002/', deprecated: false,
      },
    },
    techniques: {
      'T1059': {
        id: 'T1059', name: 'Command and Scripting Interpreter',
        tactics: ['TA0002'],
        url: 'https://attack.mitre.org/techniques/T1059/',
        deprecated: false, is_subtechnique: false,
        description: 'Adversaries may abuse command and script interpreters.',
        platforms: ['Windows', 'Linux', 'macOS'],
        data_sources: ['Process: Process Creation'],
        detection: 'Monitor process execution with command-line arguments.',
        version: '2.4',
      },
      'T1059.001': {
        id: 'T1059.001', name: 'PowerShell',
        tactics: ['TA0002'],
        url: 'https://attack.mitre.org/techniques/T1059/001/',
        deprecated: false, is_subtechnique: true, parent_id: 'T1059',
        description: 'Adversaries may abuse PowerShell commands.',
        platforms: ['Windows'],
        data_sources: ['Module: Module Load'],
        detection: 'Enable PowerShell ScriptBlock logging.',
        version: '1.5',
      },
    },
    isLoading: false,
    error: null,
    getTacticName: (id: string) => (id === 'TA0002' ? 'Execution' : id),
    getTechniqueName: (id: string) => id,
    getTacticUrl: () => '',
    getTechniqueUrl: (id: string) =>
      `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
    refresh: async () => {},
  };
  return { useMitre: () => MITRE_VALUE };
});

import { MitreCoverage } from '../MitreCoverage';

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/mitre" element={<MitreCoverage />} />
          <Route path="/mitre/:techniqueId" element={<MitreCoverage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('MitreCoverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the summary view at /mitre', async () => {
    const { findByText, container, getByText } = renderAt('/mitre');

    // Reaching this assertion at all means the page mounted without
    // a Rules-of-Hooks crash on the loaded transition.
    expect(await findByText(/MITRE ATT&CK Browser/i)).toBeInTheDocument();
    // Summary headline copy is unique (it lives in the right pane's
    // SummaryPane, while raw "100%" badges appear in 4+ places).
    expect(getByText(/Overall Coverage/i)).toBeInTheDocument();
    expect(container.querySelector('aside')).toBeTruthy();
  });

  it('renders the detail pane when a technique is selected', async () => {
    const { findByText } = renderAt('/mitre/T1059.001');
    // Description from MitreContext renders in the detail panel.
    // Wait for it (async render) — `findByText` resolves when the
    // text appears, throws on timeout. No `waitFor` wrapper needed.
    expect(await findByText(/PowerShell commands/i)).toBeInTheDocument();
  });
});
