import { useEffect, useState, type CSSProperties } from "react";
import { CompanyLogo } from "./brand";
import { IconClock } from "./icons";
import { cn } from "./ui";
import { useBranding } from "@/hooks/useBranding";
import { useAuth, type SignInWindow } from "@/store/auth";
import { idleLimitMs, idleRemainingMs } from "@/lib/idle";

/**
 * The console's footer: how long this sign-in has left, and who stands behind
 * the product.
 *
 * Its top edge is the sign-in itself. A lit line — the fuse, see .fuse in
 * index.css — runs from the left for whatever is left of it, measured against
 * the longest a sign-in may last, and its head is now. Beneath it the same
 * thing is said in words: when this sign-in ends however busy its holder is,
 * and how long it may sit untouched before that happens sooner.
 *
 * Quiet until it matters. It turns amber, and says so plainly, as the sign-in
 * nears its end and in the last minutes before the console signs out for
 * inactivity — so being signed out is never a surprise, and moving the mouse
 * visibly puts it right.
 *
 * The right-hand side is the credit: the client this console is deployed for,
 * when it has been branded, and the vendor, at full colour and a size that can
 * be read.
 */
export function Footer() {
  const year = new Date().getFullYear();
  const branding = useBranding();
  const client = branding.data?.configured ? branding.data : null;
  const signIn = useAuth((s) => s.signIn);
  const status = useSignInStatus(signIn);

  return (
    <footer className="relative z-20 flex h-12 shrink-0 items-center border-t border-line bg-surface/70 backdrop-blur">
      {status && (
        <>
          <span className="fuse" data-tone={status.tone} style={{ "--left": status.left } as CSSProperties} aria-hidden />
          <span className="fuse-head" data-tone={status.tone} style={{ "--left": status.left } as CSSProperties} aria-hidden />
        </>
      )}

      <div className="mx-auto flex w-full max-w-7xl items-center gap-4 px-4 sm:px-5">
        {status && <SignInStatus status={status} />}

        <div className="ml-auto flex shrink-0 items-center gap-4">
          {client && (
            <>
              {/* Whatever was supplied, and only that: a logo alone, a name
                  alone, or the logo with the name beside it. */}
              <span className="hidden min-w-0 items-center gap-2 text-xs text-faint md:inline-flex">
                Deployed for
                {client.client_logo && (
                  <img
                    src={client.client_logo}
                    alt={client.client_name || "Client logo"}
                    draggable={false}
                    className="h-4 w-auto max-w-[96px] select-none object-contain"
                  />
                )}
                {client.client_name.trim() && (
                  <span className="max-w-[160px] truncate font-medium text-muted">{client.client_name}</span>
                )}
              </span>
              <span className="hidden h-4 w-px bg-line-strong md:block" aria-hidden />
            </>
          )}

          <a
            href="https://vgipl.com"
            target="_blank"
            rel="noreferrer noopener"
            className="footer-mark inline-flex items-center gap-2 rounded outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
          >
            <span className="hidden text-xs text-faint sm:inline">Engineered by</span>
            <CompanyLogo className="h-[18px] w-auto" />
          </a>

          <span className="hidden text-xs tabular-nums text-faint lg:inline">© {year}</span>
        </div>
      </div>
    </footer>
  );
}

interface Status {
  tone: "calm" | "warn";
  left: number; // 0..1 of the longest sign-in, for the fuse
  headline: string;
  short: string; // the headline for a phone's width
  detail: string | null;
  explain: string; // the whole rule, on hover or focus
  announce: string; // for screen readers; changes only when the phase does
}

function SignInStatus({ status }: { status: Status }) {
  const warn = status.tone === "warn";
  return (
    <span className="group/signin relative min-w-0">
      <span
        tabIndex={0}
        aria-describedby="signin-explain"
        className="flex min-w-0 items-center gap-2.5 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
      >
        <span
          className={cn(
            "grid h-6 w-6 shrink-0 place-items-center rounded-md transition-colors",
            warn ? "bg-warn/15 text-warn" : "bg-accent-soft text-accent",
          )}
        >
          <IconClock size={14} />
        </span>
        <span className={cn("truncate text-xs font-medium tabular-nums", warn ? "text-warn" : "text-fg")}>
          <span className="sm:hidden">{status.short}</span>
          <span className="hidden sm:inline">{status.headline}</span>
        </span>
        {status.detail && <span className="hidden truncate text-xs text-faint xl:inline">{status.detail}</span>}
      </span>

      {/* Left-aligned, not centred: this sits at the footer's left edge, and a
          centred label would run off a phone's screen. */}
      <span
        id="signin-explain"
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-0 z-50 mb-3 w-max max-w-[min(26rem,calc(100vw-2rem))] rounded-md border border-line bg-surface-3 px-2.5 py-1.5 text-2xs font-medium leading-4 text-fg opacity-0 shadow-md transition-opacity duration-150 group-focus-within/signin:opacity-100 group-hover/signin:opacity-100"
      >
        {status.explain}
      </span>
      <span className="sr-only" aria-live="polite">
        {status.announce}
      </span>
    </span>
  );
}

// How near the end counts as near. The sign-in's own end warns in its last
// half hour, the idle sign-out in its last two minutes — or a quarter of each,
// on a deployment configured shorter than that.
const ENDING_MS = 30 * 60_000;
const IDLE_WARN_MS = 2 * 60_000;

function useSignInStatus(w: SignInWindow | null): Status | null {
  const idleLimit = idleLimitMs();
  const idleWarn = Math.min(IDLE_WARN_MS, idleLimit / 4);
  // A second at a time only while a countdown is on screen; otherwise the
  // minute is all anybody reads.
  const idleLeftNow = idleRemainingMs();
  const counting = idleLeftNow !== null && idleLeftNow <= idleWarn + 15_000;
  const now = useNow(counting ? 1_000 : 10_000);
  if (!w) return null;

  const left = Math.min(1, Math.max(0, (w.endsAt - now) / w.lifetimeMs));
  const idleLeft = idleRemainingMs();
  const rule = idleLimit > 0 ? `, or sooner after ${span(idleLimit)} without activity` : "";
  const explain = `This sign-in ends at ${clock(w.endsAt, now)} however busy you are${rule}.`;

  if (idleLeft !== null && idleLeft <= idleWarn) {
    return {
      tone: "warn",
      left,
      headline: `Signing out in ${mmss(idleLeft)} for inactivity`,
      short: `Signing out in ${mmss(idleLeft)}`,
      detail: "Move the mouse or press a key to stay",
      explain,
      announce: "You are about to be signed out for inactivity. Move the mouse or press a key to stay signed in.",
    };
  }
  const capLeft = w.endsAt - now;
  if (capLeft <= Math.min(ENDING_MS, w.lifetimeMs / 4)) {
    const ended = capLeft <= 0;
    return {
      tone: "warn",
      left,
      headline: ended ? "This sign-in has ended" : `Sign-in ends in ${minutes(capLeft)}`,
      short: ended ? "Sign-in ended" : `Ends in ${minutes(capLeft)}`,
      detail: ended ? "Sign in again to continue" : "Save your work, then sign in again",
      explain,
      announce: `Your sign-in ends at ${clock(w.endsAt, now)}.`,
    };
  }
  return {
    tone: "calm",
    left,
    headline: `Signed in until ${clock(w.endsAt, now)}`,
    short: `Until ${clock(w.endsAt, now)}`,
    detail: idleLimit > 0 ? `Signs out after ${span(idleLimit)} without activity` : null,
    explain,
    announce: "",
  };
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

// clock is a time of day, with the day named when it is not today.
function clock(at: number, now: number): string {
  const d = new Date(at);
  const t = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  const midnight = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((midnight(d) - midnight(new Date(now))) / 86_400_000);
  if (days === 0) return t;
  if (days === 1) return `tomorrow at ${t}`;
  return d.toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
}

function minutes(ms: number): string {
  return `${Math.max(1, Math.ceil(ms / 60_000))} min`;
}

function mmss(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// span is a configured length of time, as somebody would say it.
function span(ms: number): string {
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const r = m % 60;
  return r ? `${h} h ${r} min` : `${h} h`;
}
