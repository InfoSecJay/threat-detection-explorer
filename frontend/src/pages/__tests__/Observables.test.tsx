import { describe, it, vi, expect } from 'vitest';
import { render } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

const ev = (value: string, rules: number, by_source: Record<string, number>, context: { label: string; provider: string; channel: string } | null) =>
  ({ value, rules, sources: Object.keys(by_source), by_source, context });

vi.mock('../../hooks/useObservables', () => ({
  useObservableTypes: () => ({ data: { types: [{ type: 'eventid', label: 'Event ID', filter_key: 'event_ids', distinct: 415, top: [] }] } }),
  useObservableTop: (kind: string) => ({
    data: kind === 'eventid'
      ? {
          type: 'eventid', label: 'Event ID', distinct: 415,
          values: [
            ev('4104', 134, { splunk: 120, sigma: 14 }, { label: 'PowerShell script block', provider: 'powershell', channel: 'Microsoft-Windows-PowerShell/Operational' }),
            ev('7045', 65, { sigma: 30, elastic: 20, splunk: 10, sentinel: 3, panther: 1, okta: 1 }, { label: 'Service installed', provider: 'windows_system', channel: 'System' }),
            ev('1', 26, { sigma: 26 }, { label: 'Process creation', provider: 'sysmon', channel: 'Microsoft-Windows-Sysmon/Operational' }),
            ev('99999', 2, { panther: 2 }, null),
          ],
        }
      : kind === 'action'
        ? {
            type: 'action', label: 'API action', distinct: 3,
            values: [
              ev('ConsoleLogin', 41, { splunk: 10, elastic: 7 }, { label: 'AWS CloudTrail', provider: 'aws_cloudtrail', channel: 'AWS CloudTrail' }),
              ev('user.session.start', 23, { elastic: 14 }, { label: 'Okta System Log', provider: 'okta_system_log', channel: 'Okta System Log' }),
              ev('Orphan', 1, { panther: 1 }, null),
            ],
          }
        : { type: 'process', label: 'Process', distinct: 3, values: [ev('certutil.exe', 73, { sigma: 50, elastic: 23 }, null)] },
    isLoading: false, error: null,
  }),
}));
vi.mock('../../hooks/useDetections', () => ({ useFilterOptions: () => ({ data: { sources: ['sigma', 'splunk'] } }) }));

import { Observables } from '../Observables';

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/observables" element={<Observables />} />
        <Route path="/observables/:kind" element={<Observables />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('Observables', () => {
  it('groups event IDs by the log they belong to and labels each ID', () => {
    const { getByTestId, getAllByTestId } = renderAt('/observables/eventid');
    const order = getAllByTestId(/^channel-/).map((el) => el.getAttribute('data-testid'));
    // biggest channel first, unrecognised IDs last
    expect(order).toEqual(['channel-powershell', 'channel-windows_system', 'channel-sysmon', 'channel-unknown']);
    expect(getByTestId('channel-powershell')).toHaveTextContent('PowerShell');
    expect(getByTestId('channel-powershell')).toHaveTextContent('Microsoft-Windows-PowerShell/Operational');
    expect(getByTestId('obs-4104')).toHaveTextContent('PowerShell script block');
    expect(getByTestId('obs-1')).toHaveTextContent('Process creation');
    expect(getByTestId('channel-unknown')).toHaveTextContent('99999');
  });

  it('shows labelled per-source counts, capped with an overflow chip', () => {
    const { getByTestId } = renderAt('/observables/eventid');
    const row = getByTestId('obs-4104');
    expect(row).toHaveTextContent('SPLUNK');
    expect(row).toHaveTextContent('120');
    expect(row).toHaveTextContent('SIGMA');
    expect(getByTestId('obs-7045')).toHaveTextContent('+1'); // six sources, five shown
  });

  it('renders a flat table with a catalog link for other surfaces', () => {
    const { getByTestId, queryAllByTestId } = renderAt('/observables/process');
    expect(queryAllByTestId(/^channel-/)).toHaveLength(0);
    expect(getByTestId('kind-blurb')).toHaveTextContent('process names');
    const row = getByTestId('obs-certutil.exe');
    expect(row).toHaveTextContent('73');
    expect(row.querySelector('a[href="/detections?process_names=certutil.exe"]')).not.toBeNull();
  });

  it('groups API actions by the audit log the rules read', () => {
    const { getByTestId, getAllByTestId } = renderAt('/observables/action');
    const order = getAllByTestId(/^channel-/).map((el) => el.getAttribute('data-testid'));
    expect(order).toEqual(['channel-aws_cloudtrail', 'channel-okta_system_log', 'channel-unknown']);
    expect(getByTestId('channel-aws_cloudtrail')).toHaveTextContent('AWS CloudTrail');
    expect(getByTestId('channel-aws_cloudtrail')).toHaveTextContent('ConsoleLogin');
    expect(getByTestId('channel-unknown')).toHaveTextContent('Unattributed');
    // the platform is the group title, not repeated under every value
    expect(getByTestId('obs-ConsoleLogin')).not.toHaveTextContent('AWS CloudTrail');
  });
});
