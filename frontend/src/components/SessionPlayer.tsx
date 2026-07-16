import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Spinner, cn } from "@/components/ui";
import { IconFilm, IconPlug } from "@/components/icons";

/* The recording player.

   A session recording is stored as one blob of concatenated JPEG frames plus a
   manifest saying where each frame starts and when it was captured. The player
   fetches both once, slices the blob per frame, and draws to a canvas. That
   keeps the server free of any video encoder, and makes seeking exact: any
   frame is one drawImage away, so scrubbing lands on the real pixels rather
   than the nearest keyframe. */

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

const SPEEDS = [0.5, 1, 2, 4] as const;

export function SessionPlayer({ sessionId, onTimeChange }: { sessionId: string; onTimeChange?: (ms: number) => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [blob, setBlob] = useState<Blob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<number>(1);

  // Fetch the manifest and frames once. Both are immutable and cache hard, so a
  // reopened recording is instant.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
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
  }, [sessionId]);

  const frames = manifest?.frames ?? [];
  const total = frames.length;
  const duration = manifest?.duration_ms ?? 0;

  // Draw one frame. Decoding is async, so a fast scrub can finish out of order;
  // the generation guard keeps the last requested frame the one that lands.
  const drawGen = useRef(0);
  const draw = useCallback(
    async (i: number) => {
      const cv = canvasRef.current;
      if (!cv || !blob || !manifest || !frames[i]) return;
      const gen = ++drawGen.current;
      const f = frames[i];
      const bmp = await createImageBitmap(blob.slice(f.o, f.o + f.l, "image/jpeg"));
      if (gen !== drawGen.current) {
        bmp.close?.();
        return; // a newer frame was requested while this one decoded
      }
      const cx = cv.getContext("2d");
      if (!cx) return;
      cx.drawImage(bmp, 0, 0, cv.width, cv.height);
      bmp.close?.();
    },
    [blob, manifest, frames],
  );

  useEffect(() => {
    void draw(index);
    onTimeChange?.(frames[index]?.t ?? 0);
  }, [index, draw, frames, onTimeChange]);

  // Playback advances on real elapsed time rather than a fixed interval, so the
  // replay matches how the session actually unfolded — pauses included.
  useEffect(() => {
    if (!playing || !total) return;
    if (index >= total - 1) {
      setPlaying(false);
      return;
    }
    const gap = Math.max(frames[index + 1].t - frames[index].t, 16) / speed;
    const id = window.setTimeout(() => setIndex((i) => Math.min(i + 1, total - 1)), gap);
    return () => window.clearTimeout(id);
  }, [playing, index, total, frames, speed]);

  const togglePlay = useCallback(() => {
    if (index >= total - 1) setIndex(0); // replay from the top rather than stalling
    setPlaying((p) => !p);
  }, [index, total]);

  // Keyboard controls: space to play, arrows to step. A recording is evidence —
  // stepping frame by frame is the point.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === " ") {
        e.preventDefault();
        togglePlay();
      } else if (e.key === "ArrowRight") {
        setPlaying(false);
        setIndex((i) => Math.min(i + 1, Math.max(total - 1, 0)));
      } else if (e.key === "ArrowLeft") {
        setPlaying(false);
        setIndex((i) => Math.max(i - 1, 0));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [togglePlay, total]);

  const aspect = useMemo(
    () => (manifest ? `${manifest.width} / ${manifest.height}` : "16 / 10"),
    [manifest],
  );

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
    <div className="space-y-3">
      <div className="relative overflow-hidden rounded-xl bg-black ring-1 ring-line" style={{ aspectRatio: aspect }}>
        <canvas
          ref={canvasRef}
          width={manifest.width}
          height={manifest.height}
          className="h-full w-full"
          onClick={togglePlay}
        />
        {!playing && (
          <button
            type="button"
            onClick={togglePlay}
            aria-label="Play recording"
            className="absolute inset-0 grid place-items-center bg-black/30 transition hover:bg-black/20"
          >
            <span className="grid h-14 w-14 place-items-center rounded-full bg-white/95 shadow-lg">
              <PlayIcon />
            </span>
          </button>
        )}
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={togglePlay}
          aria-label={playing ? "Pause" : "Play"}
          className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface-2 text-fg transition hover:bg-surface-3"
        >
          {playing ? <PauseIcon /> : <PlayIcon small />}
        </button>

        <input
          type="range"
          min={0}
          max={total - 1}
          value={index}
          aria-label="Seek"
          onChange={(e) => {
            setPlaying(false);
            setIndex(Number(e.target.value));
          }}
          className="h-1 flex-1 cursor-pointer appearance-none rounded-full bg-surface-3 accent-accent"
        />

        <span className="shrink-0 font-mono text-2xs tabular-nums text-muted">
          {fmt(frames[index]?.t ?? 0)} / {fmt(duration)}
        </span>

        <div className="flex shrink-0 items-center gap-0.5 rounded-lg bg-surface-2 p-0.5">
          {SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s)}
              className={cn(
                "rounded px-1.5 py-0.5 text-2xs font-medium transition",
                speed === s ? "bg-accent text-white" : "text-muted hover:text-fg",
              )}
            >
              {s}×
            </button>
          ))}
        </div>
      </div>

      <div className="flex items-center justify-between text-2xs text-faint">
        <span className="inline-flex items-center gap-1.5">
          <IconPlug size={11} /> {total} frames · {manifest.width}×{manifest.height}
        </span>
        {manifest.truncated && (
          <span className="text-warn">Recording hit its size cap — the later part of this session isn't captured.</span>
        )}
      </div>
    </div>
  );
}

// fmt renders an elapsed-milliseconds value as m:ss.
function fmt(ms: number): string {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function PlayIcon({ small }: { small?: boolean }) {
  const n = small ? 12 : 20;
  return (
    <svg width={n} height={n} viewBox="0 0 24 24" fill="currentColor" className={small ? "" : "translate-x-0.5 text-black"}>
      <path d="M8 5v14l11-7z" />
    </svg>
  );
}

function PauseIcon() {
  return (
    <svg width={12} height={12} viewBox="0 0 24 24" fill="currentColor">
      <path d="M6 5h4v14H6zM14 5h4v14h-4z" />
    </svg>
  );
}
