/**
 * Round-trip tests for the bar <-> sheet translation (#13).
 * bar -> parse -> view -> edit -> reconcile -> bar must be lossless
 * for the supported flat-AND subset, and must refuse (stay opaque)
 * for boolean expressions where partial edits would change meaning.
 */

import { describe, it, expect } from 'vitest';
import {
  mergeTokensIntoFilters,
  parseBar,
  reconcileFilterChange,
} from '../querySync';
import type { SearchFilters } from '../../types';

const base = (over: Partial<SearchFilters> = {}): SearchFilters => ({
  offset: 0,
  limit: 25,
  ...over,
});

describe('parseBar', () => {
  it('parses flat field:value terms with quotes and aliases', () => {
    const p = parseBar('source:sigma sev:high title:"cobalt strike" powershell');
    expect(p.opaque).toBe(false);
    expect(p.tokens).toHaveLength(4);
    expect(p.tokens[0]).toMatchObject({ key: 'sources', value: 'sigma' });
    expect(p.tokens[1]).toMatchObject({ key: 'severities', value: 'high' });
    // title has no sheet section -> unmapped but still a token
    expect(p.tokens[2]).toMatchObject({ key: null, field: 'title', value: 'cobalt strike' });
    expect(p.tokens[3]).toMatchObject({ key: null, field: null, value: 'powershell' });
  });

  it('treats explicit AND as implicit', () => {
    const p = parseBar('source:sigma AND severity:high');
    expect(p.tokens.map((t) => t.value)).toEqual(['sigma', 'high']);
  });

  it('marks OR / NOT / grouped / negated queries opaque', () => {
    for (const q of [
      'source:sigma OR source:splunk',
      'NOT platform:windows',
      '(title:beacon) source:sigma',
      'severity:high -status:deprecated',
    ]) {
      expect(parseBar(q).opaque).toBe(true);
    }
  });
});

describe('view merge (bar -> sheet)', () => {
  it('bar tokens appear as checked facet values', () => {
    const filters = base({ q: 'source:sigma tech:T1059.001', severities: ['high'] });
    const view = mergeTokensIntoFilters(filters, parseBar(filters.q!));
    expect(view.sources).toEqual(['sigma']);
    expect(view.mitre_techniques).toEqual(['T1059.001']);
    expect(view.severities).toEqual(['high']); // arrays untouched
  });

  it('opaque queries leave the view as-is', () => {
    const filters = base({ q: 'source:sigma OR source:splunk' });
    const view = mergeTokensIntoFilters(filters, parseBar(filters.q!));
    expect(view.sources).toBeUndefined();
  });
});

describe('reconcile (sheet -> bar)', () => {
  it('checking a mapped facet writes a bar token', () => {
    const current = base({ q: 'source:sigma' });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, severities: ['high'] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('source:sigma severity:high');
    expect(out.severities).toEqual([]); // owned by the bar, not the array
  });

  it('unchecking a bar-owned value removes its token', () => {
    const current = base({ q: 'source:sigma severity:high free text' });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, sources: [] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('severity:high free text');
  });

  it('unchecking an array-owned value edits the array, not q', () => {
    const current = base({ q: 'tech:T1059', sources: ['splunk'] });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, sources: [] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('tech:T1059');
    expect(out.sources).toEqual([]);
  });

  it('values with spaces are quoted on serialization', () => {
    const current = base({});
    const parsed = parseBar('');
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, use_cases: ['Cobalt Strike'] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('usecase:"Cobalt Strike"');
  });

  it('opaque q: sheet adds fall back to array filters', () => {
    const current = base({ q: 'source:sigma OR source:splunk' });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, severities: ['high'] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('source:sigma OR source:splunk'); // untouched
    expect(out.severities).toEqual(['high']);
  });

  it('round-trip is lossless for untouched keys and free text', () => {
    const current = base({
      q: 'source:sigma actor:G0016 "encoded command" tech:T1059.001',
      languages: ['spl'],
    });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    // No-op edit: reconcile the view straight back.
    const out = reconcileFilterChange(current, view, { ...view }, parsed);
    expect(out.q).toBe(current.q);
    expect(out.languages).toEqual(['spl']);
    expect(out.sources).toEqual([]); // bar keeps ownership
  });
});

describe('observable surfaces (observables v2)', () => {
  it('bar observable tokens check the sheet facets', () => {
    const filters = base({ q: 'process:powershell.exe table:SecurityEvent eventid:4688' });
    const view = mergeTokensIntoFilters(filters, parseBar(filters.q!));
    expect(view.process_names).toEqual(['powershell.exe']);
    expect(view.source_tables).toEqual(['SecurityEvent']);
    expect(view.event_ids).toEqual(['4688']);
  });

  it('checking an observable facet writes its canonical bar alias', () => {
    const current = base({ q: 'severity:high' });
    const parsed = parseBar(current.q!);
    const view = mergeTokensIntoFilters(current, parsed);
    const next = { ...view, api_actions: ['CreateUser'] };
    const out = reconcileFilterChange(current, view, next, parsed);
    expect(out.q).toBe('severity:high action:CreateUser');
  });
});
