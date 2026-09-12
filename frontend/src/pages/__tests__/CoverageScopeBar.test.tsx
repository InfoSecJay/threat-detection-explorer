/**
 * "My stack" scope (#143 / DX-01): the bar edits the URL, the URL is
 * what the pages read, and the last scope follows the reader to a page
 * that opens without one.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { CoverageScopeBar } from '../actors/CoverageScopeBar';
import { SCOPE_STORAGE_KEY, useCoverageScope } from '../../hooks/useCoverageScope';

function Harness() {
  const { scope, setScope, label } = useCoverageScope();
  const { search } = useLocation();
  return (
    <div>
      <CoverageScopeBar scope={scope} setScope={setScope} />
      <div data-testid="url">{search}</div>
      <div data-testid="label">{label}</div>
    </div>
  );
}

function mount(path = '/actors') {
  return render(<MemoryRouter initialEntries={[path]}><Harness /></MemoryRouter>);
}

describe('CoverageScopeBar + useCoverageScope', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('starts unscoped: every source pressed, nothing in the URL', () => {
    mount();
    expect(screen.getByTestId('url')).toHaveTextContent('');
    expect(screen.getByTestId('scope-all')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByTestId('label')).toHaveTextContent('any vendor');
  });

  it('dropping a source writes ?sources= with the rest, and page resets', () => {
    mount('/actors?page=3&sort=gap_count');
    fireEvent.click(screen.getByTestId('scope-src-splunk'));
    const url = screen.getByTestId('url').textContent ?? '';
    expect(url).toContain('sources=');
    expect(url).not.toContain('splunk');
    expect(url).toContain('sigma');
    expect(url).toContain('sort=gap_count');
    expect(url).not.toContain('page=3');
    expect(screen.getByTestId('label')).toHaveTextContent('12 of 13 sources');
    expect(screen.getByTestId('scope-src-splunk')).toHaveAttribute('aria-pressed', 'false');
    // Remembered for the next page.
    expect(JSON.parse(localStorage.getItem(SCOPE_STORAGE_KEY) ?? '{}').sources).not.toContain('splunk');
  });

  it('the coverage toggle writes ?coverage=all and "all" clears the sources only', () => {
    mount('/actors?sources=sigma');
    fireEvent.click(screen.getByTestId('scope-coverage-toggle'));
    expect(screen.getByTestId('url')).toHaveTextContent('coverage=all');
    expect(screen.getByTestId('url')).toHaveTextContent('sources=sigma');
    fireEvent.click(screen.getByTestId('scope-all'));
    expect(screen.getByTestId('url').textContent).not.toContain('sources=');
    expect(screen.getByTestId('url')).toHaveTextContent('coverage=all');
    expect(screen.getByTestId('label')).toHaveTextContent('any vendor, incl. hunting / passthrough rules');
  });

  it('a page opened without a scope picks up the remembered one into its URL', () => {
    localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify({ sources: ['sigma', 'elastic'], coverage: 'strict' }));
    mount('/actors/G0016');
    expect(screen.getByTestId('url')).toHaveTextContent('sources=sigma%2Celastic');
    expect(screen.getByTestId('label')).toHaveTextContent('2 of 13 sources');
  });

  it('unknown source names in the URL are ignored, and selecting every source is unscoped', () => {
    mount('/actors?sources=sigma,nope');
    expect(screen.getByTestId('label')).toHaveTextContent('1 of 13 sources');
    fireEvent.click(screen.getByTestId('scope-all'));
    expect(screen.getByTestId('url').textContent).not.toContain('sources');
    expect(localStorage.getItem(SCOPE_STORAGE_KEY)).toBeNull();
  });
});
