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

/* ---- Session spans ----------------------------------------------------------
   How long a brokered session lasted is a security figure, not a cosmetic one,
   and `ended_at - started_at` is not it.

   A session is authorized from granted_from to granted_until. The reaper closes
   it when the window lapses — but the reaper only runs while the API does, so a
   host that is off overnight leaves a lapsed session sitting `active` until it
   comes back, and whatever closes it then stamps that later moment as the end.
   Subtracting start from that reports the outage as access: one session on this
   deployment read as "21h 11m" on a one-hour window whose last activity was four
   seconds in.

   So the span is measured to the earliest of: when the record closed, and when
   authorization ran out. Time after the window is not access — it is a record
   left open — and it is reported separately rather than folded in or hidden,
   because a session that outlived its window is a finding worth seeing. */
export interface SessionSpan {
  /** Time access was actually authorized and open, e.g. "1h 0m". */
  label: string;
  /** How long the record stayed open past its window, when it did. */
  overrun?: string;
  /** True while the session is still running. */
  live: boolean;
}

function fmtSpan(ms: number): string {
  const sec = Math.max(0, Math.round(ms / 1000));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${sec % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function sessionSpan(s: {
  started_at?: string;
  created_at?: string;
  ended_at?: string;
  granted_until?: string;
}): SessionSpan | null {
  const start = plausibleDate(s.started_at) ?? plausibleDate(s.created_at);
  if (!start) return null;

  const ended = plausibleDate(s.ended_at);
  const until = plausibleDate(s.granted_until);
  const close = ended ?? new Date();

  // Cap at the window only once it has actually passed. A live session inside
  // its window, or one closed early, is simply close - start.
  const capped = until && close.getTime() > until.getTime() ? until : close;
  const held = Math.max(0, capped.getTime() - start.getTime());
  const over = capped === until ? close.getTime() - until.getTime() : 0;

  return {
    label: fmtSpan(held),
    overrun: over > 60_000 ? fmtSpan(over) : undefined,
    live: !ended,
  };
}
