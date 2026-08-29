import { describe, it, expect } from 'vitest';
import { currentToken, rank, suggestFor, applyTo, fixUnknownField, buildValueIndex } from '../searchbar/suggestions';
import type { QueryFieldSpec } from '../../services/api';

const FIELDS = [
  { aliases: ['source'], kind: 'text', columns: ['source'], description: 'Repository', examples: [] },
  { aliases: ['sev', 'severity'], kind: 'text', columns: ['severity'], description: 'Severity', examples: [] },
  { aliases: ['tech', 'technique'], kind: 'list', columns: ['mitre_techniques'], description: 'ATT&CK technique', examples: [] },
] as unknown as QueryFieldSpec[];

describe('currentToken', () => {
  it('splits the token under the caret into field and value', () => {
    const t = currentToken('source:sigma sev:hi', 19);
    expect(t).toEqual({ before: 'source:sigma ', token: 'sev:hi', after: '', field: 'sev', value: 'hi' });
  });
  it('treats an open paren as a token boundary and keeps the tail', () => {
    const t = currentToken('(source:sig) AND x', 11);
    expect(t.field).toBe('source');
    expect(t.value).toBe('sig');
    expect(t.after).toBe(') AND x');
  });
});

describe('rank', () => {
  it('orders prefix before infix and drops non-matches', () => {
    const items = [{ label: 'elastic' }, { label: 'sigma' }, { label: 'splunk' }, { label: 'sublime' }];
    expect(rank(items, 's').map((i) => i.label)).toEqual(['sigma', 'splunk', 'sublime', 'elastic']);
    expect(rank(items, 'zz')).toEqual([]);
  });
});

describe('suggestFor', () => {
  it('offers canonical field aliases before a colon, secondary ones once typed', () => {
    expect(suggestFor('', 0, FIELDS, {}).suggestions.map((s) => s.value)).toEqual(['source:', 'sev:', 'tech:']);
    expect(suggestFor('seve', 4, FIELDS, {}).suggestions.map((s) => s.value)).toEqual(['severity:']);
  });
  it('offers known values after a colon and hides the value already typed', () => {
    const idx = buildValueIndex({ sources: ['sigma', 'splunk'] }, undefined);
    expect(suggestFor('source:s', 8, FIELDS, idx).suggestions.map((s) => s.value)).toEqual(['sigma', 'splunk']);
    expect(suggestFor('source:sigma', 12, FIELDS, idx).suggestions).toEqual([]); // fully typed: nothing left to offer
  });
});

describe('applyTo', () => {
  it('quotes multi-word values and lands the caret after the insertion', () => {
    const info = currentToken('actor:cob', 9);
    const { next, caret } = applyTo(info, { value: 'Cobalt Group', label: 'Cobalt Group', kind: 'value' });
    expect(next).toBe('actor:"Cobalt Group"');
    expect(caret).toBe(next.length);
  });
});

describe('fixUnknownField', () => {
  it('replaces the first unknown field even when a valid one comes first', () => {
    expect(fixUnknownField('source:sigma sevrity:high', FIELDS, 'severity')).toBe('source:sigma severity:high');
  });
});
