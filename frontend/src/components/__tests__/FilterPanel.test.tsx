/**
 * FilterPanel contract after the #25 simplification: a curated six
 * sections a first-time visitor can reason about, all facet-backed.
 * The five free-text observable sections (process names, API actions,
 * file paths, registry keys, network indicators) are gone from the
 * sheet but stay honored by the API/URL and rendered as pills.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FilterPanel } from '../FilterPanel';
import { countActiveFilters } from '../../utils/filterUtils';

vi.mock('../../hooks/useDetections', () => ({
  useFacets: () => ({
    data: {
      sources: [{ value: 'sigma', count: 4416 }, { value: 'sentinel', count: 3073 }],
      severities: [{ value: 'high', count: 100 }],
      languages: [
        { value: 'sigma', count: 4416 },
        { value: 'kql', count: 3073 },
        { value: 'osquery', count: 4 },
      ],
      mitre_tactics: [],
      mitre_techniques: [{ value: 'T1059.001', count: 12 }],
      platforms: [],
      data_sources: [],
      event_types: [],
      process_names: [{ value: 'powershell.exe', count: 900 }],
      api_actions: [],
      source_tables: [],
      event_ids: [{ value: '4688', count: 300 }],
    },
  }),
}));

vi.mock('../../hooks/useEventIds', () => ({
  useEventIds: () => ({ labels: { '4688': 'Process created' }, entries: {} }),
}));

vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({
    tactics: { TA0002: { id: 'TA0002', name: 'Execution' } },
    techniques: { 'T1059.001': { id: 'T1059.001', name: 'PowerShell' } },
  }),
}));

function setup(filters = {}) {
  const onFiltersChange = vi.fn();
  render(<FilterPanel filters={{ offset: 0, limit: 25, ...filters }} onFiltersChange={onFiltersChange} />);
  return { onFiltersChange };
}

describe('FilterPanel (#25 simplification)', () => {
  it('renders exactly the seven curated sections', () => {
    setup();
    for (const title of ['Source', 'Severity', 'Language', 'MITRE Tactics', 'MITRE Technique', 'Telemetry', 'Observables']) {
      expect(screen.getByText(title)).toBeInTheDocument();
    }
    for (const gone of ['Process Names', 'API Actions', 'File Paths', 'Registry Keys', 'Network Indicators']) {
      expect(screen.queryByText(gone)).not.toBeInTheDocument();
    }
  });

  it('observables section is facet-backed, not free text', () => {
    setup();
    fireEvent.click(screen.getByText('Observables'));
    expect(screen.getByText('powershell.exe')).toBeInTheDocument();
    expect(screen.getByText('4688')).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/e\.g\., powershell\.exe/)).not.toBeInTheDocument();
  });

  it('language options are facet-driven with corrected labels', () => {
    setup();
    fireEvent.click(screen.getByText('Language'));
    expect(screen.getByText('KQL (Sentinel / Kibana)')).toBeInTheDocument();
    expect(screen.getByText('osquery')).toBeInTheDocument(); // long tail surfaces
    expect(screen.queryByText('Lucene')).not.toBeInTheDocument(); // dead option gone
  });

  it('CLEAR appears for any pill-visible filter, including bar-only ones', () => {
    // mitre_groups has no sheet section but arrives via bar/URL and
    // renders as a pill; CLEAR must acknowledge it.
    setup({ mitre_groups: ['G0016'] });
    expect(screen.getByText('CLEAR')).toBeInTheDocument();
  });

  it('badge count matches the pill-visible key set', () => {
    expect(countActiveFilters({ offset: 0, limit: 25 })).toBe(0);
    expect(
      countActiveFilters({
        offset: 0, limit: 25,
        sources: ['sigma'],
        mitre_groups: ['G0016'],
        process_names: ['powershell.exe'], // sheet-less, URL-honored
      }),
    ).toBe(3);
  });
});
