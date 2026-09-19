/** DX-07 / #149: the `equiv:` bar token and the sheet's "Has equivalent
 * in" facet are the same filter. */
import { describe, it, expect } from 'vitest';
import { parseBar, mergeTokensIntoFilters } from '../querySync';

describe('equiv: token', () => {
  it('maps equiv:<source> onto the equivalent_in sheet filter', () => {
    const parsed = parseBar('tech:T1055 equiv:elastic');
    const merged = mergeTokensIntoFilters({ mitre_techniques: [], equivalent_in: [] }, parsed);
    expect(merged.equivalent_in).toEqual(['elastic']);
    expect(merged.mitre_techniques).toEqual(['T1055']);
  });

  it('accepts the long alias', () => {
    const merged = mergeTokensIntoFilters({ equivalent_in: [] }, parseBar('equivalent:splunk'));
    expect(merged.equivalent_in).toEqual(['splunk']);
  });

  it('leaves a negated equiv: token to the bar (opaque to the sheet)', () => {
    expect(parseBar('source:sigma -equiv:elastic').opaque).toBe(true);
  });
});
