/**
 * Event-ID labels (issue #16): the dictionary from /query/event-ids
 * renders beside raw IDs in the Event ID facet and on event-ID chips
 * in the observables panel. The raw value stays the filter key.
 */
import { describe, it, expect, vi } from 'vitest';
import { render as rtlRender, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Facet } from '../TelemetryFilter';
import { ObservablesPanel } from '../ObservablesPanel';
import type { Detection } from '../../types';

// Observable chips link to their pages, so rendering needs a router.
const render = (ui: React.ReactElement) => rtlRender(<MemoryRouter>{ui}</MemoryRouter>);

const LABELS = { '4688': 'Process created', '4624': 'Logon success' };

describe('Facet with labels', () => {
  const options = [
    { value: '4688', count: 35 },
    { value: '4624', count: 38 },
    { value: '9212', count: 5 },
  ];

  it('renders the label beside known IDs and leaves unknown IDs bare', () => {
    render(
      <Facet
        title="Event ID"
        filterKey="event_ids"
        accent="amber"
        options={options}
        selected={[]}
        onChange={() => {}}
        labels={LABELS}
      />,
    );
    expect(screen.getByText('Process created')).toBeInTheDocument();
    expect(screen.getByText('Logon success')).toBeInTheDocument();
    expect(screen.getByText('9212')).toBeInTheDocument();
    expect(screen.getByTitle('4688 - Process created')).toBeInTheDocument();
    expect(screen.getByTitle('9212')).toBeInTheDocument();
  });

  it('toggling a labelled option still emits the raw value', () => {
    const onChange = vi.fn();
    render(
      <Facet
        title="Event ID"
        filterKey="event_ids"
        accent="amber"
        options={options}
        selected={[]}
        onChange={onChange}
        labels={LABELS}
      />,
    );
    fireEvent.click(screen.getByText('Process created'));
    expect(onChange).toHaveBeenCalledWith(['4688']);
  });

  it('search matches labels, not only raw values', () => {
    const many = Array.from({ length: 8 }, (_, i) => ({ value: String(5000 + i), count: 1 }));
    render(
      <Facet
        title="Event ID"
        filterKey="event_ids"
        accent="amber"
        options={[...options, ...many]}
        selected={[]}
        onChange={() => {}}
        labels={LABELS}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText('Search event id...'), {
      target: { value: 'logon' },
    });
    expect(screen.getByText('4624')).toBeInTheDocument();
    expect(screen.queryByText('4688')).not.toBeInTheDocument();
    expect(screen.queryByText('9212')).not.toBeInTheDocument();
  });
});

describe('ObservablesPanel event-ID chips', () => {
  const observable = {
    field: 'EventID',
    type: 'event',
    subtype: 'event_id',
    values: ['4688', '9212'],
    negated: false,
  } as NonNullable<Detection['extracted_observables']>[number];

  it('labels known IDs and leaves unknown ones bare', () => {
    render(
      <ObservablesPanel observables={[observable]} sourceTables={[]} eventIdLabels={LABELS} />,
    );
    expect(screen.getByText('Process created')).toBeInTheDocument();
    expect(screen.getByTitle('4688 - Process created')).toBeInTheDocument();
    expect(screen.getByText('9212')).toBeInTheDocument();
  });

  it('renders plain chips without the dictionary', () => {
    render(<ObservablesPanel observables={[observable]} sourceTables={[]} />);
    expect(screen.getByText('4688')).toBeInTheDocument();
    expect(screen.queryByText('Process created')).not.toBeInTheDocument();
  });
});
