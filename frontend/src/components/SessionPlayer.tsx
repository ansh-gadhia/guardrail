import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";
import { api } from "@/lib/api";
import { Spinner, cn } from "@/components/ui";
import { IconFilm, IconPlug, IconDownload } from "@/components/icons";
import {
  FullscreenButton,
  PauseGlyph,
  PlayGlyph,
  PlayerButton,
  Scrubber,
  SkipGlyph,
  SpeedPicker,
  StepGlyph,
  fmtClock,
  usePlayerKeys,
  usePlayerShell,
  type PlayerHandle,
  type PlayerMarker,
} from "@/components/player/PlayerChrome";

/* The recording player.

   A session recording is stored as one blob of concatenated JPEG frames plus a
   manifest saying where each frame starts and when it was captured. The player
   fetches both once, slices the blob per frame, and draws to a canvas. That
   keeps the server free of any video encoder, and makes seeking exact: any
   frame is one drawImage away, so scrubbing lands on the real pixels rather
   than the nearest keyframe.

   Playback is driven by a clock rather than by stepping frame to frame. The
   difference shows on exactly the recordings people complain about: a screencast
   only produces frames when something changes, so a session where somebody read
   a page for twenty seconds has a twenty-second gap in the frame list. Stepping
   frame to frame froze the position readout and the scrubber for that whole
   gap — the player looked hung during the part of the session where nothing was
   moving, which is precisely when a reviewer starts to doubt what they are
   looking at. A clock runs through the gap; the frame under it simply does not
   change, which is the truth. */

interface ManifestFrame {
  t: number; // ms from the start of the recording
  o: number; // byte offset into the frame blob
  l: number; // byte length
}

interface Manifest {
  version: number;
  width: number;
  height: number;
  started_at: string;
  duration_ms: number;
  frames: ManifestFrame[];
  truncated?: boolean;
}

const SPEEDS = [0.25, 0.5, 1, 2, 4, 8] as const;
// How far the skip buttons and the arrow keys move. Ten seconds is the web's
// settled answer for a button; five is small enough for an arrow key to be a
// nudge rather than a jump.
const SKIP_MS = 10_000;
const NUDGE_MS = 5_000;

export const SessionPlayer = forwardRef<PlayerHandle, {
  sessionId: string;
  /** Called as playback moves, so a timeline alongside can follow it. Throttled. */
  onTimeChange?: (ms: number) => void;
  /** Moments to flag on the scrubber. */
  markers?: PlayerMarker[];
  /** Reports the recording's wall-clock start, once the manifest is in. */
  onManifest?: (m: { startedAt: string; durationMs: number }) => void;
}>(function SessionPlayer({ sessionId, onTimeChange, markers, onManifest }, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const drawGen = useRef(0);
  const drawn = useRef(-1);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [blob, setBlob] = useState<Blob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // The playhead is held in a ref as well as in state. State is what renders;
  // the ref is what the clock below reads. Keeping only state meant the clock
  // effect closed over the position it started with — so a seek made while
  // playing was overwritten on the very next frame, and the scrubber sprang
  // back under the operator's finger.
  const [pos, setPos] = useState(0); // ms from the start of the recording
  const posRef = useRef(0);
  const putPos = useCallback((ms: number) => {
    posRef.current = ms;
    setPos(ms);
  }, []);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<number>(1);

  const { shellRef, fullscreen, toggleFullscreen, controlsHidden, wake } = usePlayerShell();

  // Fetch the manifest and frames once. Both are immutable and cache hard, so a
  // reopened recording is instant.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    putPos(0);
    setPlaying(false);
    drawn.current = -1; // a different recording; whatever is on the canvas is stale
    (async () => {
      try {
        const [m, f] = await Promise.all([
          api.get<Manifest>(`/sessions/${sessionId}/recording/manifest`),
          api.get(`/sessions/${sessionId}/recording/frames`, { responseType: "blob" }),
        ]);
        if (cancelled) return;
        setManifest(m.data);
        setBlob(f.data as Blob);
      } catch {
        if (!cancelled) setError("This recording could not be loaded.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionId, putPos]);

  const frames = useMemo(() => manifest?.frames ?? [], [manifest]);
  const total = frames.length;
  // A screencast's last frame stands until the session ends, so the recording is
  // as long as the manifest says even when no frame was captured near the end.
  // Falling back to the last frame's timestamp made every player report a
  // duration shorter than the session it came from.
  const duration = Math.max(manifest?.duration_ms ?? 0, frames[total - 1]?.t ?? 0);

  useEffect(() => {
    if (manifest && onManifest) {
      onManifest({ startedAt: manifest.started_at, durationMs: Math.max(manifest.duration_ms, duration) });
    }
  }, [manifest, duration, onManifest]);

  // The frame standing at a given moment: the last one captured at or before it.
  // Binary search, because scrubbing asks this on every pointer move and a long
  // session has tens of thousands of frames.
  const frameAt = useCallback(
    (ms: number) => {
      if (total === 0) return 0;
      let lo = 0;
      let hi = total - 1;
      let best = 0;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (frames[mid].t <= ms) {
          best = mid;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      return best;
    },
    [frames, total],
  );

  const index = frameAt(pos);

  // Decoding is async, so a fast scrub can finish out of order; the generation
  // guard keeps the last requested frame the one that lands. `drawn` skips the
  // decode entirely when the frame on the canvas is already the right one, which
  // is most ticks: a screencast frame stands for as long as nothing changes.
  useEffect(() => {
    const cv = canvasRef.current;
    const f = frames[index];
    if (!cv || !blob || !manifest || !f || drawn.current === index) return;
    drawn.current = index;
    const gen = ++drawGen.current;
    void (async () => {
      const bmp = await createImageBitmap(blob.slice(f.o, f.o + f.l, "image/jpeg"));
      if (gen !== drawGen.current) {
        bmp.close?.();
        return; // a newer frame was requested while this one decoded
      }
      const cx = cv.getContext("2d");
      if (!cx) {
        bmp.close?.();
        return;
      }
      cx.drawImage(bmp, 0, 0, cv.width, cv.height);
      bmp.close?.();
    })();
  }, [index, frames, blob, manifest]);

  // Report position outward at a few times a second. The clock below runs at the
  // display's refresh rate, and handing that straight to a parent would re-render
  // the whole session view sixty times a second to move one highlight.
  const lastReport = useRef(0);
  useEffect(() => {
    if (!onTimeChange) return;
    const now = performance.now();
    // Throttled only while playing. A seek is a deliberate move to one moment,
    // and dropping it because it landed inside the throttle window would leave
    // the timeline highlighting the wrong entry until playback resumed.
    if (playing && now - lastReport.current < 200) return;
    lastReport.current = now;
    onTimeChange(pos);
  }, [pos, playing, onTimeChange]);

  // Playback clock. Advances on real elapsed time so the replay matches how the
  // session actually unfolded — pauses included — and so speed is a real
  // multiplier rather than a per-frame delay.
  useEffect(() => {
    if (!playing || duration <= 0) return;
    let raf = 0;
    let last = performance.now();
    let painted = 0;
    const tick = (now: number) => {
      const next = Math.min(posRef.current + (now - last) * speed, duration);
      last = now;
      posRef.current = next;
      if (next >= duration) {
        putPos(duration);
        setPlaying(false);
        return;
      }
      // ~25 state writes a second is past the point where more is visible, and
      // well under the point where React becomes the bottleneck.
      if (now - painted >= 40) {
        painted = now;
        setPos(next);
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, duration, putPos]);

  const seekTo = useCallback(
    (ms: number) => putPos(Math.min(Math.max(ms, 0), duration)),
    [duration, putPos],
  );
  useImperativeHandle(ref, () => ({ seekTo }), [seekTo]);

  const togglePlay = useCallback(() => {
    if (duration <= 0) return;
    // Replaying from the end would look like a dead player: nothing moves and the
    // button says pause. Rewind first.
    if (posRef.current >= duration) putPos(0);
    setPlaying((p) => !p);
  }, [duration, putPos]);

  const nudge = useCallback(
    (ms: number) => seekTo(pos + ms),
    [pos, seekTo],
  );
  const step = useCallback(
    (by: number) => {
      setPlaying(false);
      const next = Math.min(Math.max(index + by, 0), Math.max(total - 1, 0));
      seekTo(frames[next]?.t ?? 0);
    },
    [index, total, frames, seekTo],
  );

  usePlayerKeys(
    shellRef,
    useMemo(
      () => ({
        " ": togglePlay,
        k: togglePlay,
        ArrowLeft: () => nudge(-NUDGE_MS),
        ArrowRight: () => nudge(NUDGE_MS),
        j: () => nudge(-SKIP_MS),
        l: () => nudge(SKIP_MS),
        ",": () => step(-1),
        ".": () => step(1),
        Home: () => seekTo(0),
        End: () => seekTo(duration),
        f: toggleFullscreen,
        ...Object.fromEntries(
          Array.from({ length: 10 }, (_, n) => [String(n), () => seekTo((duration * n) / 10)]),
        ),
      }),
      [togglePlay, nudge, step, seekTo, duration, toggleFullscreen],
    ),
    !loading && !error && total > 0,
  );

  // Saving the frame on screen is how a finding leaves a review: it goes into the
  // ticket. Rendering it from the canvas costs nothing and means the reviewer
  // does not screenshot their own monitor to quote the evidence.
  const saveFrame = useCallback(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    cv.toBlob((b) => {
      if (!b) return;
      const url = URL.createObjectURL(b);
      const a = document.createElement("a");
      a.href = url;
      a.download = `guardrail-${sessionId.slice(0, 8)}-${fmtClock(pos).replace(/:/g, "")}.png`;
      a.click();
      URL.revokeObjectURL(url);
    }, "image/png");
  }, [sessionId, pos]);

  const aspect = useMemo(
    () => (manifest ? `${manifest.width} / ${manifest.height}` : "16 / 10"),
    [manifest],
  );

  // The wall-clock moment the playhead is sitting on. A reviewer correlating a
  // recording with a firewall log or a ticket needs the actual time, not an
  // offset from a start they would have to go and look up.
  const wall = useMemo(() => {
    if (!manifest?.started_at) return null;
    const base = new Date(manifest.started_at).getTime();
    if (!Number.isFinite(base)) return null;
    return new Date(base + pos).toLocaleTimeString();
  }, [manifest, pos]);

  if (loading) {
    return (
      <div className="flex h-72 items-center justify-center gap-2 rounded-xl bg-black/40 text-sm text-muted">
        <Spinner /> Loading recording…
      </div>
    );
  }
  if (error || !manifest || !total) {
    return (
      <div className="flex h-72 flex-col items-center justify-center gap-2 rounded-xl border border-line bg-surface-2/40 text-center">
        <IconFilm size={22} className="text-faint" />
        <p className="text-sm text-muted">{error ?? "No video was captured for this session."}</p>
        <p className="max-w-sm text-2xs text-faint">
          Screen recording captures sessions rendered in the isolated browser. A session that ended before any frame
          was painted has nothing to replay.
        </p>
      </div>
    );
  }

  return (
    <div
      ref={shellRef}
      tabIndex={0}
      onMouseMove={fullscreen ? wake : undefined}
      className={cn(
        "space-y-3 outline-none",
        fullscreen && "flex h-full w-full flex-col justify-center gap-0 bg-black p-0",
      )}
    >
      <div
        className={cn(
          "relative overflow-hidden bg-black",
          fullscreen ? "min-h-0 flex-1" : "rounded-xl ring-1 ring-line",
        )}
        style={fullscreen ? undefined : { aspectRatio: aspect }}
      >
        <canvas
          ref={canvasRef}
          width={manifest.width}
          height={manifest.height}
          className="h-full w-full object-contain"
          onClick={togglePlay}
          onDoubleClick={toggleFullscreen}
        />
        {!playing && (
          <button
            type="button"
            onClick={togglePlay}
            aria-label="Play recording"
            className="absolute inset-0 grid place-items-center bg-black/30 transition hover:bg-black/20"
          >
            <span className="grid h-14 w-14 place-items-center rounded-full bg-white/95 shadow-lg">
              <span className="translate-x-0.5 text-black">
                <PlayGlyph size={20} />
              </span>
            </span>
          </button>
        )}
      </div>

      <div
        className={cn(
          "flex items-center gap-2 transition-opacity",
          fullscreen && "bg-black/85 px-4 py-3",
          controlsHidden && "pointer-events-none opacity-0",
        )}
      >
        <PlayerButton label={playing ? "Pause (space)" : "Play (space)"} onClick={togglePlay}>
          {playing ? <PauseGlyph /> : <PlayGlyph />}
        </PlayerButton>
        <PlayerButton label="Back 10 seconds (j)" onClick={() => nudge(-SKIP_MS)}>
          <SkipGlyph back />
        </PlayerButton>
        <PlayerButton label="Forward 10 seconds (l)" onClick={() => nudge(SKIP_MS)}>
          <SkipGlyph />
        </PlayerButton>
        <PlayerButton label="Previous frame (,)" onClick={() => step(-1)} disabled={index <= 0}>
          <StepGlyph back />
        </PlayerButton>
        <PlayerButton label="Next frame (.)" onClick={() => step(1)} disabled={index >= total - 1}>
          <StepGlyph />
        </PlayerButton>

        <Scrubber
          position={pos}
          duration={duration}
          markers={markers}
          onScrubStart={() => setPlaying(false)}
          onSeek={seekTo}
        />

        <span className={cn("shrink-0 font-mono text-2xs tabular-nums", fullscreen ? "text-white/80" : "text-muted")}>
          {fmtClock(pos)} / {fmtClock(duration)}
        </span>

        <SpeedPicker speed={speed} speeds={SPEEDS} onChange={setSpeed} />
        <PlayerButton label="Save this frame as PNG" onClick={saveFrame}>
          <IconDownload size={14} />
        </PlayerButton>
        <FullscreenButton fullscreen={fullscreen} onToggle={toggleFullscreen} />
      </div>

      {!fullscreen && (
        <div className="flex flex-wrap items-center justify-between gap-2 text-2xs text-faint">
          <span className="inline-flex items-center gap-1.5">
            <IconPlug size={11} /> frame {index + 1} of {total} · {manifest.width}×{manifest.height}
            {wall && <> · {wall}</>}
          </span>
          {manifest.truncated && (
            <span className="text-warn">Recording hit its size cap — the later part of this session isn't captured.</span>
          )}
        </div>
      )}
    </div>
  );
});
