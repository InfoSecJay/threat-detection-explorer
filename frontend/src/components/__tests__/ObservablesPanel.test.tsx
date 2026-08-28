import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ObservablesPanel } from '../ObservablesPanel';

const obs = (over: Partial<{ field: string; values: string[]; type: string; subtype: string; negated: boolean }> = {}) => ({
  field: 'Image', values: ['powershell.exe'], type: 'process', subtype: 'process_name', negated: false, ...over,
});

describe('ObservablesPanel (observables v2)', () => {
  it('groups by type in canonical order and shows field provenance', () => {
    render(
      <ObservablesPanel
        complexity="moderate"
        sourceTables={['SecurityEvent']}
        observables={[
          obs({ type: 'network', subtype: 'port', field: 'DestinationPort', values: ['443'] }),
          obs(),
          obs({ type: 'registry', subtype: 'registry_key', field: 'TargetObject', values: ['HKLM\\Run'] }),
        ]}
      />,
    );
    const groups = screen.getAllByTestId(/observable-group-/).map((el) => el.getAttribute('data-testid'));
    expect(groups).toEqual(['observable-group-process', 'observable-group-registry', 'observable-group-network']);
    expect(screen.getByText('Image')).toBeInTheDocument();
    expect(screen.getByText('process name')).toBeInTheDocument();
    expect(screen.getByText('SecurityEvent')).toBeInTheDocument();
    expect(screen.getByText('moderate query')).toBeInTheDocument();
  });

  it('marks negated conditions explicitly', () => {
    render(<ObservablesPanel sourceTables={[]} observables={[obs({ negated: true })]} />);
    expect(screen.getByText('NOT')).toBeInTheDocument();
  });

  it('skips empty-value rows and maps unknown types to Other', () => {
    render(
      <ObservablesPanel
        sourceTables={[]}
        observables={[obs({ values: [] }), obs({ type: 'martian', subtype: 'unknown', values: ['x'] })]}
      />,
    );
    expect(screen.queryByTestId('observable-group-process')).not.toBeInTheDocument();
    expect(screen.getByTestId('observable-group-other')).toBeInTheDocument();
  });

  it('caps long value lists with an overflow marker', () => {
    const many = Array.from({ length: 15 }, (_, i) => `v${i}`);
    render(<ObservablesPanel sourceTables={[]} observables={[obs({ values: many })]} />);
    expect(screen.getByText('+3 more')).toBeInTheDocument();
  });
});
