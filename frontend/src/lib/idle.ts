import { useEffect } from "react";

// The console's inactivity sign-out.
//
// The server enforces an idle limit as well, measured between refreshes, and
// that covers a browser that was closed and a laptop that slept. It cannot cover
// a tab left open: the tab's own background polling refreshes the token every
// few minutes, and the server has no way to tell that from a person. Only the
// browser knows whether anybody has touched the keyboard or the mouse, so the
// browser keeps this clock — with the limit the server hands it, not one of its
// own.
//
// The clock is shared between tabs through localStorage. They are one sign-in:
// working in one tab keeps the others signed in, and when the limit passes they
// all go together.

const KEY = "guardrail.lastActivity";
// localStorage is written at most this often. Pointer movement fires dozens of
// events a second; the limit is measured in minutes.
const WRITE_EVERY_MS = 5_000;
const CHECK_EVERY_MS = 10_000;

let limitMs = 0;
let lastLocal = Date.now(); // loading the page is itself somebody doing something
let lastWritten = 0;

// setIdleLimit takes the server's idle_timeout_seconds. 0 or absent disables.
export function setIdleLimit(seconds: number | undefined): void {
  limitMs = seconds && seconds > 0 ? seconds * 1000 : 0;
}

function markActivity(force = false): void {
  const now = Date.now();
  lastLocal = now;
  if (force || now - lastWritten >= WRITE_EVERY_MS) {
    lastWritten = now;
    try {
      localStorage.setItem(KEY, String(now));
    } catch {
      /* storage refused — this tab still keeps its own clock */
    }
  }
}

function lastActivity(): number {
  let shared = 0;
  try {
    shared = Number(localStorage.getItem(KEY)) || 0;
  } catch {
    /* as above */
  }
  return Math.max(lastLocal, shared);
}

// idleExpired is true once nobody has touched any tab of this console for
// longer than the limit.
export function idleExpired(): boolean {
  return limitMs > 0 && Date.now() - lastActivity() > limitMs;
}

// idleLimitMs is the configured limit; 0 when there is none.
export function idleLimitMs(): number {
  return limitMs;
}

// idleRemainingMs is how long until the console signs out for inactivity, or
// null when it never will.
export function idleRemainingMs(): number | null {
  return limitMs > 0 ? limitMs - (Date.now() - lastActivity()) : null;
}

// idleReason is what the sign-in page says afterwards, in the server's voice.
export function idleReason(): string {
  const m = Math.round(limitMs / 60_000);
  return `you were signed out after ${m} minute${m === 1 ? "" : "s"} of inactivity`;
}

const EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "scroll"] as const;

// watchIdle listens for activity and calls onIdle, repeatedly, while the limit
// has passed. Capture phase, so a component that stops propagation — a terminal
// swallowing its keystrokes — still counts as somebody typing.
export function watchIdle(onIdle: () => void): () => void {
  const onActivity = () => markActivity();
  for (const e of EVENTS) window.addEventListener(e, onActivity, { capture: true, passive: true });
  const timer = window.setInterval(() => {
    if (idleExpired()) onIdle();
  }, CHECK_EVERY_MS);
  return () => {
    for (const e of EVENTS) window.removeEventListener(e, onActivity, { capture: true });
    window.clearInterval(timer);
  };
}

// useKeepAwake holds the console signed in while `active` is true.
//
// For the pages that show a live session. The session runs in an iframe, and
// what somebody types into it never reaches this page — so an hour in an RDP
// desktop would otherwise look like an hour away from the keyboard. The session
// has its own idle policy, enforced by the gateway, which is the one that
// should decide how long it may sit untouched. The heartbeat goes through
// localStorage, so it holds every tab, not just this one: otherwise another tab
// timing out would sign the whole browser out from under the session.
export function useKeepAwake(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    markActivity(true);
    const t = window.setInterval(() => markActivity(true), 30_000);
    return () => window.clearInterval(t);
  }, [active]);
}
