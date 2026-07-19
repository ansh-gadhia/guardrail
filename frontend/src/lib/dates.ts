// Shared timestamp guard.
//
// Some backend rows carry an unset time, which Go serializes as the zero value
// "0001-01-01T00:00:00Z". `new Date("0001-01-01T00:00:00Z")` is a VALID Date (not
// NaN), so naive rendering shows "1/1/0001" or a relative time of "~739814d ago".
// A real GuardRail timestamp is never before 2001, so treat anything implausibly
// old — or unparseable — as absent, and let callers render a dash / "unknown".
export const MIN_PLAUSIBLE_TS = Date.UTC(2001, 0, 1);

/** Parse an ISO timestamp, returning null for missing, invalid, or zero-value dates. */
export function plausibleDate(iso?: string | null): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) || d.getTime() < MIN_PLAUSIBLE_TS ? null : d;
}
