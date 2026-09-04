/**
 * Event-type hierarchy in the sidebar (#104): parents render with a
 * union count and an expander, children appear under them, selecting a
 * parent filters on the parent value alone (the backend expands it) and
 * the children read as included rather than selectable.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { GroupedFacet, TelemetryFilter } from '../TelemetryFilter';
import type { SearchFilters } from '../../types';

const GROUPS = [
  { value: 'file_event', count: 100, children: [{ value: 'file_delete', count: 24 }, { value: 'file_change', count: 3 }] },
  { value: 'authentication', count: 671, children: [] },
  { value: 'unknown', count: 5, children: [] },
];

describe('GroupedFacet', () => {
  it('renders parents collapsed, expands to children, keeps unknown last', () => {
    const onChange = vi.fn();
    render(<GroupedFacet title="Event Type" accent="orange" groups={GROUPS} selected={[]} onChange={onChange} />);

    const facet = screen.getByTestId('grouped-facet');
    const labels = within(facet).getAllByText(/^(file_event|authentication|unknown)$/).map((el) => el.textContent);
    expect(labels).toEqual(['authentication', 'file_event', 'unknown']);
    expect(within(facet).getByText('100')).toBeInTheDocument();
    expect(screen.queryByText('file_delete')).toBeNull();

    fireEvent.click(screen.getByLabelText('Expand file_event'));
    expect(screen.getByText('file_delete')).toBeInTheDocument();
    expect(screen.getByText('24')).toBeInTheDocument();
  });

  it('selecting a parent sends only the parent; children show as included', () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <GroupedFacet title="Event Type" accent="orange" groups={GROUPS} selected={[]} onChange={onChange} />,
    );
    fireEvent.click(screen.getByTitle('file_event - includes 2 specific kinds').closest('label')!.querySelector('input')!);
    expect(onChange).toHaveBeenCalledWith(['file_event']);

    rerender(<GroupedFacet title="Event Type" accent="orange" groups={GROUPS} selected={['file_event']} onChange={onChange} />);
    fireEvent.click(screen.getByLabelText('Expand file_event'));
    const child = screen.getByTitle('file_delete - included by file_event');
    const box = child.querySelector('input') as HTMLInputElement;
    expect(box.checked).toBe(true);
    expect(box.disabled).toBe(true);
  });

  it('a child is selectable on its own when its parent is not selected', () => {
    const onChange = vi.fn();
    render(<GroupedFacet title="Event Type" accent="orange" groups={GROUPS} selected={[]} onChange={onChange} />);
    fireEvent.click(screen.getByLabelText('Expand file_event'));
    fireEvent.click(screen.getByTitle('file_delete').querySelector('input')!);
    expect(onChange).toHaveBeenCalledWith(['file_delete']);
  });

  it('search matches children and auto-expands their parent', () => {
    const many = [...GROUPS, ...Array.from({ length: 5 }, (_, i) => ({ value: `g${i}`, count: 1, children: [] }))];
    render(<GroupedFacet title="Event Type" accent="orange" groups={many} selected={[]} onChange={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText('Search event type...'), { target: { value: 'delete' } });
    expect(screen.getByText('file_delete')).toBeInTheDocument();
    expect(screen.queryByText('file_change')).toBeNull();
    expect(screen.queryByText('authentication')).toBeNull();
  });
});

describe('TelemetryFilter', () => {
  const filters: SearchFilters = {};
  it('uses the grouped facet when groups are provided and the flat one otherwise', () => {
    const { rerender } = render(
      <TelemetryFilter
        filters={filters}
        onFiltersChange={() => {}}
        options={{ platforms: [], data_sources: [], event_types: [{ value: 'file_delete', count: 24 }], event_type_groups: GROUPS }}
      />,
    );
    expect(screen.getByTestId('grouped-facet')).toBeInTheDocument();
    rerender(
      <TelemetryFilter
        filters={filters}
        onFiltersChange={() => {}}
        options={{ platforms: [], data_sources: [], event_types: [{ value: 'file_delete', count: 24 }] }}
      />,
    );
    expect(screen.queryByTestId('grouped-facet')).toBeNull();
    expect(screen.getByText('file_delete')).toBeInTheDocument();
  });
});
