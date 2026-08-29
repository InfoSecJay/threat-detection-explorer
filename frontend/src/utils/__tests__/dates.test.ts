import { describe, it, expect } from 'vitest';
import { parseApiDate, daysSince } from '../dates';

describe('parseApiDate', () => {
  it('treats a naive ISO datetime as UTC, not local', () => {
    // Regardless of the test runner's TZ, 18:00 with no zone must be 18:00Z.
    expect(parseApiDate('2026-08-29T18:00:00').toISOString()).toBe('2026-08-29T18:00:00.000Z');
    expect(parseApiDate('2026-08-29T18:00:00.123456').getTime()).toBe(Date.UTC(2026, 7, 29, 18, 0, 0, 123));
    expect(parseApiDate('2026-08-29T18:00').toISOString()).toBe('2026-08-29T18:00:00.000Z');
  });

  it('leaves zone-qualified strings alone', () => {
    expect(parseApiDate('2026-08-29T18:00:00Z').toISOString()).toBe('2026-08-29T18:00:00.000Z');
    expect(parseApiDate('2026-08-29T18:00:00+02:00').toISOString()).toBe('2026-08-29T16:00:00.000Z');
  });

  it('leaves date-only strings alone (spec already parses them as UTC)', () => {
    expect(parseApiDate('2023-01-01').toISOString()).toBe('2023-01-01T00:00:00.000Z');
  });

  it('returns an Invalid Date for empty or junk input', () => {
    expect(isNaN(parseApiDate(null).getTime())).toBe(true);
    expect(isNaN(parseApiDate('').getTime())).toBe(true);
    expect(isNaN(parseApiDate('not a date').getTime())).toBe(true);
  });
});

describe('daysSince', () => {
  const now = Date.UTC(2026, 7, 29, 12, 0, 0);

  it('counts whole days in UTC', () => {
    expect(daysSince('2026-08-29T01:00:00', now)).toBe(0);
    expect(daysSince('2026-08-28T11:59:00', now)).toBe(1);
    expect(daysSince('2026-08-01T00:00:00', now)).toBe(28);
  });

  it('clamps future timestamps to 0 instead of going negative', () => {
    expect(daysSince('2026-08-29T20:00:00', now)).toBe(0);
  });

  it('is null for invalid input', () => {
    expect(daysSince(null, now)).toBeNull();
    expect(daysSince('nope', now)).toBeNull();
  });
});
