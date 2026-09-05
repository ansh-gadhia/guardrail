import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";
import { cn } from "@/components/ui";
import { IconMaximize, IconMinimize } from "@/components/icons";

/* The furniture a replay needs to be a video player.

   GuardRail has two replay surfaces that decode completely different things — a
   canvas of JPEG frames for an isolated browser session, and a Guacamole
   instruction stream for a desktop — and a reviewer should not be able to tell
   which one they are looking at from the controls. Everything that is about
   *watching* rather than *decoding* lives here so both get it, and so neither
   can drift into having a keyboard shortcut the other lacks.

   The controls themselves are unremarkable, and that is the point: a recording
   is evidence, and evidence is examined by scrubbing back and forth, stepping,
   slowing down and going full screen. A play button and a slider is a demo. */

/** What a player exposes to the page around it, so a timeline entry can drive it. */
export interface PlayerHandle {
  /** Jumps to an offset in milliseconds from the start of the recording. */
  seekTo(ms: number): void;
}

/** One flag on the scrubber — a moment the timeline knows about. */
export interface PlayerMarker {
  ms: number;
  label: string;
  tone?: "accent" | "warn" | "danger";
}

const MARKER_TONE: Record<NonNullable<PlayerMarker["tone"]>, string> = {
  accent: "bg-accent",
  warn: "bg-warn",
  danger: "bg-danger",
};

/** Renders elapsed milliseconds as m:ss, or h:mm:ss once it runs past an hour. */
export function fmtClock(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const s = total % 60;
  const m = Math.floor(total / 60) % 60;
  const h = Math.floor(total / 3600);
  const mm = h > 0 ? String(m).padStart(2, "0") : String(m);
  return `${h > 0 ? `${h}:` : ""}${mm}:${String(s).padStart(2, "0")}`;
}

/* ---- Fullscreen, focus and idle-hide ------------------------------------- */

/**
 * Wires up the things a player needs from the browser rather than from its own
 * state: the fullscreen API, whether the controls should currently be visible,
 * and whether this player is the thing the keyboard is talking to.
 */
export function usePlayerShell() {
  const shellRef = useRef<HTMLDivElement>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [idle, setIdle] = useState(false);
  const idleTimer = useRef<number | undefined>(undefined);

  // The browser owns fullscreen state — the user can leave with Esc, or the
  // window manager can drop out of it — so it is read from the event rather than
  // assumed from the click that requested it.
  useEffect(() => {
    const sync = () => setFullscreen(document.fullscreenElement === shellRef.current);
    document.addEventListener("fullscreenchange", sync);
    return () => document.removeEventListener("fullscreenchange", sync);
  }, []);

  const toggleFullscreen = useCallback(() => {
    const el = shellRef.current;
    if (!el) return;
    if (document.fullscreenElement === el) {
      void document.exitFullscreen().catch(() => {});
    } else {
      // Focus follows the request so the keyboard shortcuts keep working once the
      // rest of the page is no longer on screen to be tabbed to.
      void el.requestFullscreen().then(() => el.focus({ preventScroll: true })).catch(() => {});
    }
  }, []);

  // Controls fade while the pointer is still, and only in fullscreen: a player
  // sitting in a page is small, its controls are not in the way, and hiding them
  // there would just make the component feel broken.
  const wake = useCallback(() => {
    setIdle(false);
    window.clearTimeout(idleTimer.current);
    idleTimer.current = window.setTimeout(() => setIdle(true), 2600);
  }, []);

  useEffect(() => {
    if (!fullscreen) {
      window.clearTimeout(idleTimer.current);
      setIdle(false);
      return;
    }
    wake();
    return () => window.clearTimeout(idleTimer.current);
  }, [fullscreen, wake]);

  return { shellRef, fullscreen, toggleFullscreen, controlsHidden: fullscreen && idle, wake };
}

/**
 * Registers a player's keyboard shortcuts, scoped so they belong to the player.
 *
 * The obvious implementation — a keydown listener on window — is what was here,
 * and it means Space toggles playback while somebody is typing a space into a
 * search box on the same page. So the keys are claimed only when this player is
 * plausibly what the user is driving: it is fullscreen, or it holds focus, or
 * nothing else on the page does. Typing targets are always left alone.
 */
export function usePlayerKeys(
  shellRef: React.RefObject<HTMLElement | null>,
  handlers: Record<string, () => void>,
  enabled = true,
) {
  const latest = useRef(handlers);
  useLayoutEffect(() => {
    latest.current = handlers;
  });

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      const el = shellRef.current;
      if (!el || e.metaKey || e.ctrlKey || e.altKey) return;

      const target = e.target as HTMLElement | null;
      if (target?.isContentEditable || (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;

      const active = document.activeElement;
      const mine =
        document.fullscreenElement === el ||
        el.contains(active) ||
        active === null ||
        active === document.body;
      if (!mine) return;

      const fn = latest.current[e.key] ?? latest.current[e.key.toLowerCase()];
      if (!fn) return;
      e.preventDefault();
      fn();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [shellRef, enabled]);
}

/* ---- The scrubber --------------------------------------------------------- */

/**
 * A seek bar that can be dragged, clicked anywhere along, and carries the
 * timeline's markers.
 *
 * It is a div rather than <input type=range> for two reasons that matter here:
 * a range input cannot show where the interesting moments are, and it cannot be
 * scrubbed continuously without the value jumping in step increments. Both are
 * the difference between skimming a recording and hunting through it.
 */
export function Scrubber({
  position,
  duration,
  markers = [],
  onSeek,
  onScrubStart,
  disabled,
}: {
  position: number;
  duration: number;
  markers?: PlayerMarker[];
  onSeek: (ms: number) => void;
  onScrubStart?: () => void;
  disabled?: boolean;
}) {
  const barRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [dragging, setDragging] = useState(false);

  const msAt = useCallback(
    (clientX: number) => {
      const el = barRef.current;
      if (!el || duration <= 0) return 0;
      const r = el.getBoundingClientRect();
      const frac = r.width > 0 ? (clientX - r.left) / r.width : 0;
      return Math.round(Math.min(1, Math.max(0, frac)) * duration);
    },
    [duration],
  );

  const down = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (disabled || duration <= 0) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    setDragging(true);
    onScrubStart?.();
    onSeek(msAt(e.clientX));
  };
  const move = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (disabled || duration <= 0) return;
    setHover(msAt(e.clientX));
    if (dragging) onSeek(msAt(e.clientX));
  };
  const up = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (dragging) {
      e.currentTarget.releasePointerCapture(e.pointerId);
      setDragging(false);
    }
  };

  const pct = duration > 0 ? (Math.min(position, duration) / duration) * 100 : 0;

  return (
    <div
      ref={barRef}
      role="slider"
      aria-label="Seek"
      aria-valuemin={0}
      aria-valuemax={Math.max(duration, 0)}
      aria-valuenow={Math.min(position, duration)}
      aria-valuetext={`${fmtClock(position)} of ${fmtClock(duration)}`}
      aria-disabled={disabled || undefined}
      tabIndex={-1}
      onPointerDown={down}
      onPointerMove={move}
      onPointerUp={up}
      onPointerCancel={up}
      onPointerLeave={() => setHover(null)}
      className={cn(
        "group relative flex-1 cursor-pointer touch-none select-none py-2",
        disabled && "cursor-not-allowed opacity-50",
      )}
    >
      {/* Track */}
      <div className="relative h-1 w-full rounded-full bg-white/15">
        <div className="absolute inset-y-0 left-0 rounded-full bg-accent" style={{ width: `${pct}%` }} />

        {/* What the timeline knows about, laid over the track. A reviewer opening
            a 40-minute recording should be able to see where the four things
            that happened are, rather than scrub for them. */}
        {duration > 0 &&
          markers.map((m, i) => (
            <span
              key={`${m.ms}-${i}`}
              title={`${fmtClock(m.ms)} · ${m.label}`}
              className={cn(
                "absolute -top-0.5 h-2 w-[3px] -translate-x-1/2 rounded-sm opacity-80",
                MARKER_TONE[m.tone ?? "accent"],
              )}
              style={{ left: `${Math.min(100, Math.max(0, (m.ms / duration) * 100))}%` }}
            />
          ))}

        {/* Thumb. Small until the bar is hovered, so it does not sit on top of
            the markers while you are trying to read them. */}
        <span
          className={cn(
            "absolute top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white shadow ring-1 ring-black/20 transition-transform",
            dragging ? "scale-110" : "scale-0 group-hover:scale-100",
          )}
          style={{ left: `${pct}%` }}
        />
      </div>

      {/* Where the pointer would land, in recording time. */}
      {hover !== null && duration > 0 && (
        <span
          className="pointer-events-none absolute -top-5 -translate-x-1/2 rounded bg-black/85 px-1.5 py-0.5 font-mono text-2xs tabular-nums text-white"
          style={{ left: `${Math.min(100, Math.max(0, (hover / duration) * 100))}%` }}
        >
          {fmtClock(hover)}
        </span>
      )}
    </div>
  );
}

/* ---- Buttons -------------------------------------------------------------- */

export function PlayerButton({
  label,
  onClick,
  disabled,
  active,
  children,
  wide,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  active?: boolean;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      className={cn(
        "grid h-8 shrink-0 place-items-center rounded-lg text-fg transition",
        wide ? "px-2" : "w-8",
        active ? "bg-accent text-white" : "bg-surface-2 hover:bg-surface-3",
        disabled && "cursor-not-allowed opacity-40 hover:bg-surface-2",
      )}
    >
      {children}
    </button>
  );
}

export function FullscreenButton({ fullscreen, onToggle }: { fullscreen: boolean; onToggle: () => void }) {
  return (
    <PlayerButton label={fullscreen ? "Exit full screen (f)" : "Full screen (f)"} onClick={onToggle}>
      {fullscreen ? <IconMinimize size={14} /> : <IconMaximize size={14} />}
    </PlayerButton>
  );
}

export function SpeedPicker({
  speed,
  speeds,
  onChange,
}: {
  speed: number;
  speeds: readonly number[];
  onChange: (s: number) => void;
}) {
  return (
    <div className="flex shrink-0 items-center gap-0.5 rounded-lg bg-surface-2 p-0.5">
      {speeds.map((s) => (
        <button
          key={s}
          type="button"
          onClick={() => onChange(s)}
          aria-pressed={speed === s}
          className={cn(
            "rounded px-1.5 py-0.5 text-2xs font-medium tabular-nums transition",
            speed === s ? "bg-accent text-white" : "text-muted hover:text-fg",
          )}
        >
          {s}×
        </button>
      ))}
    </div>
  );
}

export const PlayGlyph = ({ size = 12 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
    <path d="M8 5v14l11-7z" />
  </svg>
);

export const PauseGlyph = ({ size = 12 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
    <path d="M6 5h4v14H6zM14 5h4v14h-4z" />
  </svg>
);

/** Jump-back / jump-forward, with the seconds written on the glyph. */
export const SkipGlyph = ({ back, secs = 10 }: { back?: boolean; secs?: number }) => (
  <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} aria-hidden>
    {back ? (
      <path d="M11 5 6 9.5 11 14M6.5 9.5H14a5 5 0 0 1 0 10h-3" strokeLinecap="round" strokeLinejoin="round" />
    ) : (
      <path d="m13 5 5 4.5-5 4.5M17.5 9.5H10a5 5 0 0 0 0 10h3" strokeLinecap="round" strokeLinejoin="round" />
    )}
    <text x="12" y="9" textAnchor="middle" fontSize="7" fill="currentColor" stroke="none">
      {secs}
    </text>
  </svg>
);

export const StepGlyph = ({ back }: { back?: boolean }) => (
  <svg width={12} height={12} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
    {back ? <path d="M18 5v14l-9-7zM6 5h2v14H6z" /> : <path d="M6 5v14l9-7zM16 5h2v14h-2z" />}
  </svg>
);
