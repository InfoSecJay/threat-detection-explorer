/**
 * Tests for the localStorage-backed saved/recent query hook (#14).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useSavedQueries } from '../useSavedQueries';

describe('useSavedQueries', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('records recents newest-first, deduped, capped at 8', () => {
    const { result } = renderHook(() => useSavedQueries());
    act(() => {
      for (let i = 0; i < 10; i++) result.current.recordRecent(`q${i}`);
      result.current.recordRecent('q5'); // dedupe + move to front
    });
    expect(result.current.recent[0].query).toBe('q5');
    expect(result.current.recent).toHaveLength(8);
    expect(result.current.recent.filter((r) => r.query === 'q5')).toHaveLength(1);
  });

  it('ignores empty submissions', () => {
    const { result } = renderHook(() => useSavedQueries());
    act(() => result.current.recordRecent('   '));
    expect(result.current.recent).toHaveLength(0);
  });

  it('starring promotes out of recents into saved', () => {
    const { result } = renderHook(() => useSavedQueries());
    act(() => {
      result.current.recordRecent('source:sigma');
      result.current.star('source:sigma');
    });
    expect(result.current.recent).toHaveLength(0);
    expect(result.current.saved).toHaveLength(1);
    expect(result.current.saved[0].name).toBe('source:sigma');
  });

  it('rename and unstar', () => {
    const { result } = renderHook(() => useSavedQueries());
    act(() => {
      result.current.star('actor:APT29', 'apt29 rules');
      result.current.rename('actor:APT29', 'cozy bear');
    });
    expect(result.current.saved[0].name).toBe('cozy bear');
    act(() => result.current.unstar('actor:APT29'));
    expect(result.current.saved).toHaveLength(0);
  });

  it('persists across hook instances via localStorage', () => {
    const first = renderHook(() => useSavedQueries());
    act(() => {
      first.result.current.recordRecent('tech:T1059');
      first.result.current.star('sev:critical');
    });
    first.unmount();

    const second = renderHook(() => useSavedQueries());
    expect(second.result.current.recent[0].query).toBe('tech:T1059');
    expect(second.result.current.saved[0].query).toBe('sev:critical');
  });

  it('clearRecent empties recents only', () => {
    const { result } = renderHook(() => useSavedQueries());
    act(() => {
      result.current.recordRecent('a');
      result.current.star('b');
      result.current.clearRecent();
    });
    expect(result.current.recent).toHaveLength(0);
    expect(result.current.saved).toHaveLength(1);
  });
});
