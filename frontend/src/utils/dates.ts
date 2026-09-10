/**
 * Date helpers for API timestamps.
 *
 * The backend stores and serializes naive UTC (`utcnow()` strips
 * tzinfo, pydantic emits `2026-08-29T18:00:00` with no `Z`). Browsers
 * parse an offset-less ISO datetime as LOCAL time, which shifted every
 * "Synced", "Last sync", freshness dot and relative-date on the site
 * by the viewer's UTC offset (a sync at 18:00 UTC rendered as
 * "6:00 PM EDT"). Route every API timestamp through `parseApiDate`.
 */

// ISO datetime with a `T` separator and NO trailing zone designator
// (`Z` or `+hh:mm`). Date-only strings (`2023-01-01`) are already
// parsed as UTC by the spec and are left alone.
const NAIVE_ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/;

/** Parse an API timestamp as UTC. Returns an Invalid Date for junk. */
export function parseApiDate(value: string | null | undefined): Date {
  if (!value) return new Date(NaN);
  const s = value.trim();
  return new Date(NAIVE_ISO_DATETIME.test(s) ? `${s}Z` : s);
}

/** Whole days between `value` and now, never negative (clock skew or
 * a rule dated slightly in the future reads as "today", not "-1d"). */
export function daysSince(value: string | null | undefined, now: number = Date.now()): number | null {
  const d = parseApiDate(value);
  if (isNaN(d.getTime())) return null;
  return Math.max(0, Math.floor((now - d.getTime()) / 86_400_000));
}

/** Format a date-only API value (a calendar date, not an instant --
 * upstream `date`/`modified`/`creation_date`/`updated_date` fields) as
 * ISO `YYYY-MM-DD`, read from UTC components. `parseApiDate` already
 * anchors these to UTC midnight; `toLocaleDateString()` on that Date
 * re-renders in the viewer's zone and rolls the day back for anyone
 * west of UTC. Do not use this for true timestamps (e.g. sync time),
 * which should keep rendering in the viewer's own zone. */
export function formatCalendarDate(value: string | null | undefined): string {
  const d = parseApiDate(value);
  if (isNaN(d.getTime())) return 'unknown';
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}
