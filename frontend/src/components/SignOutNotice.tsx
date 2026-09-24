import { useEffect, useState, type ReactNode } from "react";
import { IconClock } from "./icons";
import { useAuth } from "@/store/auth";
import { idleLimitMs, idleRemainingMs } from "@/lib/idle";

/**
 * A warning that the console is about to sign this person out — shown only
 * when it is about to, and gone the rest of the time.
 *
 * Two cases. Nobody has touched the console for nearly the idle limit: a
 * countdown, and a button to stay (pressing it is itself the activity that
 * resets the clock, like any other key or click). Or the sign-in is near the
 * most it may last, which nothing can extend: when it ends, so work can be
 * saved first, dismissible.
 *
 * Both lengths come from the server with the sign-in; nothing here is a
 * number of its own beyond how early to warn.
 */
const IDLE_WARN_MS = 2 * 60_000;
const END_WARN_MS = 10 * 60_000;

export function SignOutNotice() {
  const signIn = useAuth((s) => s.signIn);
  const [dismissedEnd, setDismissedEnd] = useState(false);

  // A second at a time only while a countdown could be close; otherwise the
  // check is cheap and rare.
  const idleLimit = idleLimitMs();
  const idleWarn = Math.min(IDLE_WARN_MS, idleLimit / 4);
  const idleLeftNow = idleRemainingMs();
  const near = idleLeftNow !== null && idleLeftNow <= idleWarn + 15_000;
  const now = useNow(near ? 1_000 : 10_000);

  const idleLeft = idleRemainingMs();
  if (idleLeft !== null && idleLeft <= idleWarn && idleLeft > 0) {
    return (
      <Notice
        title={`Signing out in ${mmss(idleLeft)}`}
        body="Nothing has been touched in this console for a while. It signs out soon to keep it safe."
        announce="You are about to be signed out for inactivity."
        action={
          // No handler needed: the press is itself the activity that resets
          // the idle clock (see watchIdle), and the notice goes with it.
          <button type="button" className="btn-primary text-xs">
            Stay signed in
          </button>
        }
      />
    );
  }

  if (signIn && !dismissedEnd) {
    const left = signIn.endsAt - now;
    if (left > 0 && left <= Math.min(END_WARN_MS, signIn.lifetimeMs / 4)) {
      return (
        <Notice
          title={`Your sign-in ends at ${clock(signIn.endsAt)}`}
          body="Save your work, then sign in again to carry on."
          announce={`Your sign-in ends at ${clock(signIn.endsAt)}.`}
          action={
            <button type="button" className="btn-ghost text-xs" onClick={() => setDismissedEnd(true)}>
              Dismiss
            </button>
          }
        />
      );
    }
  }
  return null;
}

function Notice({ title, body, announce, action }: { title: string; body: string; announce: string; action: ReactNode }) {
  return (
    <div className="fixed bottom-16 left-1/2 z-50 w-[24rem] max-w-[calc(100vw-2rem)] -translate-x-1/2">
      <div className="animate-slideup rounded-xl border border-warn/40 bg-surface p-3 shadow-lg ring-1 ring-warn/20">
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-warn/15 text-warn">
            <IconClock size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold tabular-nums text-fg">{title}</div>
            <p className="mt-0.5 text-xs text-muted">{body}</p>
          </div>
        </div>
        <div className="mt-2.5 flex justify-end">{action}</div>
      </div>
      {/* Said once per warning, not every tick of the countdown. An alert,
          because it arrives already holding its text, which a polite live
          region is not reliably read out for. */}
      <span className="sr-only" role="alert">
        {announce}
      </span>
    </div>
  );
}

function useNow(everyMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    setNow(Date.now());
    const t = window.setInterval(() => setNow(Date.now()), everyMs);
    return () => window.clearInterval(t);
  }, [everyMs]);
  return now;
}

// clock is a time of day; the day is named when it is not today.
export function clock(at: number): string {
  const d = new Date(at);
  const t = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  return d.toDateString() === new Date().toDateString()
    ? t
    : d.toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
}

function mmss(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
