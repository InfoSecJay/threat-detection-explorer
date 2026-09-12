/** "My stack" coverage scope (#143 / DX-01).
 *
 * Which repos an actor's coverage, gaps and Named counts are scored
 * against (`?sources=sigma,elastic`; none = every tracked source), and
 * whether the hunting / building-block / passthrough / indicator rules
 * the default scope leaves out should count (`?coverage=all`).
 *
 * The URL is the source of truth, so a pasted link reproduces the
 * numbers. localStorage only remembers the last scope so it follows
 * the reader from /actors to /actors/:id without every link carrying
 * it: a page that opens with no scope in its URL writes the remembered
 * one in (history replace), and the address bar always states what
 * the numbers measure. Clearing the scope clears the memory too. */

import { useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ALL_SOURCES } from '../constants/sources';
import type { CoverageMode } from '../services/api';

export const SCOPE_STORAGE_KEY = 'de.coverageScope';

export interface CoverageScopeState {
  sources: string[] | null;
  coverage: CoverageMode;
}

export const DEFAULT_SCOPE: CoverageScopeState = { sources: null, coverage: 'strict' };

const KNOWN = new Set<string>(ALL_SOURCES);

function normalise(sources: string[] | null | undefined, coverage: string | null | undefined): CoverageScopeState {
  const kept = (sources ?? []).filter((s) => KNOWN.has(s));
  // Every source selected is the same as no selection.
  const scoped = kept.length > 0 && kept.length < ALL_SOURCES.length ? ALL_SOURCES.filter((s) => kept.includes(s)) : null;
  return { sources: scoped, coverage: coverage === 'all' ? 'all' : 'strict' };
}

/** The scope named by the URL, or null when neither param is present. */
export function parseScopeParams(params: URLSearchParams): CoverageScopeState | null {
  const raw = params.get('sources');
  const coverage = params.get('coverage');
  if (raw === null && coverage === null) return null;
  return normalise(raw === null ? null : raw.split(',').map((s) => s.trim()).filter(Boolean), coverage);
}

export function isScoped(scope: CoverageScopeState): boolean {
  return scope.sources !== null || scope.coverage === 'all';
}

/** One phrase for a headline: what the coverage numbers were scored against. */
export function describeScope(scope: CoverageScopeState): string {
  const who = scope.sources === null ? 'any vendor' : `${scope.sources.length} of ${ALL_SOURCES.length} sources`;
  return scope.coverage === 'all' ? `${who}, incl. hunting / passthrough rules` : who;
}

function load(): CoverageScopeState | null {
  try {
    const raw = localStorage.getItem(SCOPE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<CoverageScopeState>;
    return normalise(Array.isArray(parsed.sources) ? parsed.sources : null, parsed.coverage);
  } catch {
    return null;
  }
}

function save(scope: CoverageScopeState | null): void {
  try {
    if (scope && isScoped(scope)) localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(scope));
    else localStorage.removeItem(SCOPE_STORAGE_KEY);
  } catch {
    /* preference simply does not persist when site data is blocked */
  }
}

function writeScope(params: URLSearchParams, scope: CoverageScopeState): void {
  if (scope.sources) params.set('sources', scope.sources.join(','));
  else params.delete('sources');
  if (scope.coverage === 'all') params.set('coverage', 'all');
  else params.delete('coverage');
  // A scope change re-ranks the list; page 1 is the only honest page.
  params.delete('page');
}

export function useCoverageScope() {
  const [searchParams, setSearchParams] = useSearchParams();
  const fromUrl = useMemo(() => parseScopeParams(searchParams), [searchParams]);

  useEffect(() => {
    if (fromUrl) {
      save(fromUrl);
      return;
    }
    const remembered = load();
    if (remembered && isScoped(remembered)) {
      const next = new URLSearchParams(searchParams);
      writeScope(next, remembered);
      setSearchParams(next, { replace: true });
    }
  }, [fromUrl, searchParams, setSearchParams]);

  const scope = fromUrl ?? DEFAULT_SCOPE;

  const setScope = useCallback(
    (next: CoverageScopeState) => {
      const clean = normalise(next.sources, next.coverage);
      save(clean);
      const params = new URLSearchParams(searchParams);
      writeScope(params, clean);
      setSearchParams(params);
    },
    [searchParams, setSearchParams],
  );

  return { scope, setScope, isScoped: isScoped(scope), label: describeScope(scope) };
}
