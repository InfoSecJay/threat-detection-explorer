/** Newest-first is the catalog default; free text in the bar flips it
 * to Relevance so title matches still rank first. */
import { describe, it, expect } from 'vitest';
import { defaultSortFor, hasFreeText, NEWEST_FIRST, RELEVANCE } from '../sortDefaults';

describe('defaultSortFor', () => {
  it('sorts the empty catalog newest-first', () => {
    expect(defaultSortFor({})).toBe(NEWEST_FIRST);
    expect(defaultSortFor({ q: '' })).toBe(NEWEST_FIRST);
    expect(defaultSortFor({ q: '   ' })).toBe(NEWEST_FIRST);
  });

  it('keeps field-only queries newest-first', () => {
    expect(defaultSortFor({ q: 'tech:T1055 source:sigma' })).toBe(NEWEST_FIRST);
    expect(defaultSortFor({ q: '(source:sigma OR source:elastic)' })).toBe(NEWEST_FIRST);
    expect(defaultSortFor({ q: 'actor:"Mustang Panda"' })).toBe(NEWEST_FIRST);
    expect(defaultSortFor({ q: 'tech:T1055* AND severity:high' })).toBe(NEWEST_FIRST);
  });

  it('ranks by relevance once the bar carries a bare term', () => {
    expect(defaultSortFor({ q: 'citrix' })).toBe(RELEVANCE);
    expect(defaultSortFor({ q: 'tech:T1055 citrix' })).toBe(RELEVANCE);
    expect(defaultSortFor({ q: '"lateral movement"' })).toBe(RELEVANCE);
    expect(defaultSortFor({ q: '+powershell source:sigma' })).toBe(RELEVANCE);
  });

  it('does not count negated terms, which the backend never ranks on', () => {
    expect(hasFreeText('-citrix source:sigma')).toBe(false);
    expect(hasFreeText('NOT citrix')).toBe(false);
    expect(hasFreeText('NOT "lateral movement"')).toBe(false);
    expect(hasFreeText('powershell -citrix')).toBe(true);
  });

  it('treats the legacy search param as free text', () => {
    expect(defaultSortFor({ search: 'citrix' })).toBe(RELEVANCE);
  });
});
