/**
 * Building-block tri-state filter (issue #26): the scalar filter gets a
 * pill, counts as one active filter, and clears to undefined.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ActiveFilterPills } from '../ActiveFilterPills';
import { countActiveFilters } from '../../utils/filterUtils';

vi.mock('../../hooks/useEventIds', () => ({
  useEventIds: () => ({ labels: {}, entries: {} }),
}));

describe('building_block filter', () => {
  it('counts as one active filter in either direction', () => {
    expect(countActiveFilters({})).toBe(0);
    expect(countActiveFilters({ building_block: true })).toBe(1);
    expect(countActiveFilters({ building_block: false })).toBe(1);
    expect(countActiveFilters({ building_block: true, statuses: ['test', 'stable'] })).toBe(3);
  });

  it('renders a pill and clears the filter when removed', () => {
    const onFiltersChange = vi.fn();
    render(<ActiveFilterPills filters={{ building_block: true }} onFiltersChange={onFiltersChange} />);
    expect(screen.getByText(/Building blocks/)).toBeInTheDocument();
    expect(screen.getByText(/only/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Building blocks/i }));
    expect(onFiltersChange).toHaveBeenCalledWith(
      expect.objectContaining({ building_block: undefined, offset: 0 }),
    );
  });

  it('reads "hidden" for the exclude direction', () => {
    render(<ActiveFilterPills filters={{ building_block: false }} onFiltersChange={() => {}} />);
    expect(screen.getByText(/hidden/)).toBeInTheDocument();
  });
});
