/**
 * Keyboard-interaction tests for the query SearchBar.
 *
 * Pins the fix for the Enter trap: with a fully-typed value like
 * `software:S0002`, the dropdown still matched its own suggestion,
 * Enter kept re-applying it, and the query could never be submitted.
 * Now nothing is highlighted by default — Enter submits, arrow keys
 * highlight, Tab completes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SearchBar } from '../SearchBar';

vi.mock('../../hooks/useQueryFields', () => ({
  useQueryFields: () => ({
    data: {
      fields: [
        {
          aliases: ['software', 'tool', 'malware'],
          kind: 'list_mitre_software',
          description: 'ATT&CK Software',
          examples: ['software:Mimikatz'],
        },
        {
          aliases: ['severity', 'sev'],
          kind: 'enum',
          description: 'Rule severity',
          examples: ['severity:high'],
        },
      ],
    },
  }),
}));

vi.mock('../../hooks/useDetections', () => ({
  useFilterOptions: () => ({
    data: {
      sources: [],
      statuses: [],
      severities: ['high', 'critical'],
      languages: [],
      platforms: [],
      data_sources: [],
      event_types: [],
      use_cases: [],
      mitre_groups: [{ value: 'G0016' }],
      mitre_software: [{ value: 'S0002' }, { value: 'S0154' }],
    },
  }),
}));

vi.mock('../../contexts/MitreContext', () => ({
  useMitre: () => ({ techniques: {} }),
}));

function setup(initial = '') {
  const onSubmit = vi.fn();
  render(
    <MemoryRouter>
      <SearchBar value={initial} onSubmit={onSubmit} />
    </MemoryRouter>
  );
  const input = screen.getByRole('textbox') as HTMLInputElement;
  return { input, onSubmit };
}

function type(input: HTMLInputElement, text: string) {
  fireEvent.focus(input);
  fireEvent.change(input, { target: { value: text, selectionStart: text.length } });
  input.setSelectionRange(text.length, text.length);
  fireEvent.keyUp(input, { key: 'End' });
}

describe('SearchBar keyboard interaction', () => {
  it('Enter submits a fully-typed query even while suggestions are open', () => {
    const { input, onSubmit } = setup();
    type(input, 'software:S000');
    // Dropdown is open with matching values…
    expect(screen.getByRole('listbox')).toBeTruthy();
    // …but Enter with nothing highlighted submits the typed query.
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSubmit).toHaveBeenCalledWith('software:S000');
  });

  it('Enter submits when the typed value exactly matches a suggestion', () => {
    const { input, onSubmit } = setup();
    type(input, 'software:S0002');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSubmit).toHaveBeenCalledWith('software:S0002');
  });

  it('an exact-match value no longer appears as a suggestion', () => {
    const { input } = setup();
    type(input, 'software:S0002');
    expect(screen.queryByRole('listbox')?.textContent ?? '').not.toContain('S0002');
  });

  it('ArrowDown + Enter applies the highlighted suggestion instead of submitting', () => {
    const { input, onSubmit } = setup();
    type(input, 'software:S00');
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(input.value).toBe('software:S0002');
  });

  it('Tab completes the top suggestion without submitting', () => {
    const { input, onSubmit } = setup();
    type(input, 'soft');
    fireEvent.keyDown(input, { key: 'Tab' });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(input.value).toBe('software:');
  });

  it('default field list offers only canonical aliases (no malware:/tool:/sev:)', () => {
    const { input } = setup();
    fireEvent.focus(input);
    const list = screen.getByRole('listbox').textContent ?? '';
    expect(list).toContain('software:');
    expect(list).toContain('severity:');
    expect(list).not.toContain('malware:');
    expect(list).not.toContain('tool:');
    expect(list).not.toContain('sev:');
  });

  it('typing a secondary alias still surfaces it', () => {
    const { input } = setup();
    type(input, 'malw');
    const list = screen.getByRole('listbox').textContent ?? '';
    expect(list).toContain('malware:');
  });
});

describe('saved queries panel (#14)', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('records a recent query on submit and lists it in the panel', () => {
    const { onSubmit, input } = setup();
    fireEvent.change(input, { target: { value: 'severity:high' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onSubmit).toHaveBeenCalledWith('severity:high');

    fireEvent.click(screen.getByLabelText('Saved and recent queries'));
    expect(screen.getByTitle('severity:high')).toBeInTheDocument();
  });

  it('starring a recent moves it to saved; clicking runs it', () => {
    const { onSubmit, input } = setup();
    fireEvent.change(input, { target: { value: 'source:sigma' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    fireEvent.click(screen.getByLabelText('Saved and recent queries'));
    fireEvent.click(screen.getByLabelText('Save source:sigma'));
    // Now in SAVED with an unstar control.
    expect(screen.getByLabelText('Remove source:sigma from saved')).toBeInTheDocument();

    fireEvent.click(screen.getByTitle('source:sigma'));
    expect(onSubmit).toHaveBeenLastCalledWith('source:sigma');
  });

  it('empty submits are not recorded', () => {
    const { input } = setup();
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.click(screen.getByLabelText('Saved and recent queries'));
    expect(screen.getByText('submitted queries show up here')).toBeInTheDocument();
  });
});
