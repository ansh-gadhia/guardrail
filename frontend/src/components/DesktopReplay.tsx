import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";
import { AxiosError } from "axios";
import Guacamole from "guacamole-common-js";
import { api } from "@/lib/api";
import { blobReplayTunnel } from "@/lib/guacRecordingTunnel";
import { Spinner, cn } from "@/components/ui";
import { IconAlert } from "@/components/icons";
import {
  FullscreenButton,
  PauseGlyph,
  PlayGlyph,
  PlayerButton,
  Scrubber,
  SkipGlyph,
  fmtClock,
  usePlayerKeys,
  usePlayerShell,
  type PlayerHandle,
  type PlayerMarker,
} from "@/components/player/PlayerChrome";

/* Playback for an RDP/VNC session.

   Unlike the other two players this one decodes nothing itself. guacd wrote the
   session as a Guacamole protocol dump — the same instruction stream the live
   viewer consumes, with timing in it — and guacamole-common-js replays that
   natively. So there is no manifest to pair with the blob and no frame slicing:
   the dump is already seekable, because SessionRecording indexes the frames as it
   parses.

   That difference is why a desktop recording reported has_video false and read as
   "nothing was captured" while the bytes sat in the blob store the whole time. A
   desktop is not frames. */

type Phase = "loading" | "ready" | "error";

// How far the skip buttons and keys move. Matched to the frame player so the two
// replay surfaces behave identically under the same hands.
const SKIP_MS = 10_000;
const NUDGE_MS = 5_000;

export const DesktopReplay = forwardRef<PlayerHandle, {
  sessionId: string;
  /** Called as playback moves, so a timeline alongside can follow it. Throttled. */
  onTimeChange?: (ms: number) => void;
  /** Moments to flag on the scrubber. */
  markers?: PlayerMarker[];
}>(function DesktopReplay({ sessionId, onTimeChange, markers }, ref) {
  const mountRef = useRef<HTMLDivElement>(null);
  const recRef = useRef<Guacamole.SessionRecording | null>(null);
  const roRef = useRef<ResizeObserver | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [message, setMessage] = useState("");
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  // Seeking is asynchronous — the recording replays every instruction between
  // here and there. While that runs the slider must follow the thumb, not the
  // position callbacks, or it snaps back under the operator's finger.
  const [scrubbing, setScrubbing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let recording: Guacamole.SessionRecording | null = null;

    void (async () => {
      // Fetch and parse are separated so the error names which one failed. A
      // blanket "could not be fetched" over both sent every diagnosis in the
      // wrong direction: a 404 (no bytes stored), a 403 (RBAC), a 500 (blob read
      // failed server-side) and an unparseable dump all read identically, so a
      // storage problem looked like a player problem and back again.
      let blob: Blob;
      try {
        const res = await api.get(`/sessions/${sessionId}/recording/desktop`, { responseType: "blob" });
        blob = res.data as Blob;
      } catch (e) {
        if (cancelled) return;
        const status = e instanceof AxiosError ? e.response?.status : undefined;
        // A blob-typed error response still arrives as a Blob; pull the server's
        // message out of it so a 500 says why instead of just its number.
        let detail = "";
        const body = (e instanceof AxiosError ? e.response?.data : undefined) as Blob | undefined;
        if (body && typeof body.text === "function") {
          try {
            detail = (await body.text()).slice(0, 200);
          } catch {
            /* not text — leave it */
          }
        }
        setMessage(
          status === 404
            ? "The server has no desktop recording stored for this session (nothing was captured, or it was deleted)."
            : status === 403
              ? "You do not have permission to view this recording."
              : status
                ? `The server refused the recording (HTTP ${status}).${detail ? " " + detail : ""}`
                : "The recording could not be fetched — the request did not reach the server.",
        );
        setPhase("error");
        return;
      }
      if (cancelled) return;

      // Zero bytes means the row exists but nothing was written — the classic
      // "recorded, but guacd could not write the file" outcome. Say that, rather
      // than handing an empty blob to the parser to fail on obscurely.
      if (!blob || blob.size === 0) {
        setMessage("The recording is empty — the session was recorded but no data was written to it.");
        setPhase("error");
        return;
      }

      const mount = mountRef.current;
      if (!mount) return;

      try {
        // Feed the recording through a tunnel that replays the fetched blob,
        // because SessionRecording(Blob) is broken in guacamole-common-js 1.5.0 —
        // it parses `undefined` and throws. See blobReplayTunnel. The tunnel path
        // is exercised instead, which the library implements correctly, so the
        // recording must be told to connect() to start reading.
        recording = new Guacamole.SessionRecording(blobReplayTunnel(blob));
        recRef.current = recording;

        const display = recording.getDisplay();
        mount.appendChild(display.getElement());

        // Fit the replay to its container, as the live viewer does. A recording
        // of a 1920x1080 desktop letterboxed into a modal is unreadable, and
        // unreadable evidence is not evidence.
        const fit = () => {
          const w = mount.clientWidth;
          const h = mount.clientHeight;
          const dw = display.getWidth();
          const dh = display.getHeight();
          if (!w || !h || !dw || !dh) return;
          display.scale(Math.min(w / dw, h / dh));
        };
        const ro = new ResizeObserver(fit);
        ro.observe(mount);
        display.onresize = fit;
        roRef.current = ro;

        // Frames arrive as the blob is parsed, so the duration grows while
        // loading. Track it rather than reading it once, or the slider ends at
        // whatever length happened to be parsed when the first frame landed.
        recording.onprogress = (total: number) => {
          if (!cancelled) setDuration(total);
        };
        recording.onload = () => {
          if (cancelled) return;
          setDuration(recording?.getDuration() ?? 0);
          setPhase("ready");
          fit();
        };
        recording.onerror = (msg: string) => {
          if (cancelled) return;
          setMessage(msg || "The recording could not be replayed.");
          setPhase("error");
        };
        recording.onseek = (pos: number) => {
          if (!cancelled) setPosition(pos);
        };
        recording.onplay = () => !cancelled && setPlaying(true);
        recording.onpause = () => !cancelled && setPlaying(false);

        // Required for a tunnel-backed recording (unlike a Blob, which the library
        // would read on its own): this is what starts the replay tunnel reading
        // the bytes. Set every handler above first, so no early frame is missed.
        if (!cancelled) recording.connect();
      } catch {
        // The bytes arrived but could not be turned into a playable recording —
        // a genuine format problem, not a transport one.
        if (!cancelled) {
          setMessage("The recording was downloaded but could not be read as a session recording.");
          setPhase("error");
        }
      }
    })();

    return () => {
      cancelled = true;
      roRef.current?.disconnect();
      roRef.current = null;
      try {
        // Stops parsing too: abandoning a half-downloaded recording should not
        // leave it decoding into a display nobody is looking at.
        recording?.pause();
        recording?.abort();
      } catch {
        /* already finished — nothing to stop */
      }
      recRef.current = null;
    };
  }, [sessionId]);

  const { shellRef, fullscreen, toggleFullscreen, controlsHidden, wake } = usePlayerShell();
  const ready = phase === "ready";

  // Report position outward a few times a second, so a timeline alongside can
  // follow the playhead without re-rendering the page on every parsed frame.
  const lastReport = useRef(0);
  useEffect(() => {
    if (!onTimeChange) return;
    const now = performance.now();
    // Throttled only while playing, so a deliberate seek always reaches the
    // timeline rather than being dropped for landing inside the window.
    if (playing && now - lastReport.current < 200) return;
    lastReport.current = now;
    onTimeChange(position);
  }, [position, playing, onTimeChange]);

  // Seeking replays every instruction between here and there, so it is
  // asynchronous: the slider follows the thumb until the seek lands, or it snaps
  // back under the operator's finger.
  const seekTo = useCallback((ms: number) => {
    const rec = recRef.current;
    if (!rec) return;
    const to = Math.min(Math.max(Math.round(ms), 0), rec.getDuration());
    setScrubbing(true);
    setPosition(to);
    rec.pause();
    rec.seek(to, () => setScrubbing(false));
  }, []);
  useImperativeHandle(ref, () => ({ seekTo }), [seekTo]);

  const toggle = useCallback(() => {
    const rec = recRef.current;
    if (!rec || phase !== "ready") return;
    if (rec.isPlaying()) rec.pause();
    else {
      // Replaying from the end would look like a dead player: nothing moves and
      // the button says pause. Rewind first.
      if (rec.getPosition() >= rec.getDuration()) rec.seek(0);
      rec.play();
    }
  }, [phase]);

  const nudge = useCallback((ms: number) => seekTo(position + ms), [position, seekTo]);

  usePlayerKeys(
    shellRef,
    useMemo(
      () => ({
        " ": toggle,
        k: toggle,
        ArrowLeft: () => nudge(-NUDGE_MS),
        ArrowRight: () => nudge(NUDGE_MS),
        j: () => nudge(-SKIP_MS),
        l: () => nudge(SKIP_MS),
        Home: () => seekTo(0),
        End: () => seekTo(duration),
        f: toggleFullscreen,
        ...Object.fromEntries(
          Array.from({ length: 10 }, (_, n) => [String(n), () => seekTo((duration * n) / 10)]),
        ),
      }),
      [toggle, nudge, seekTo, duration, toggleFullscreen],
    ),
    ready,
  );

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
          "relative w-full overflow-hidden bg-[#0b0e14]",
          fullscreen ? "min-h-0 flex-1" : "aspect-video rounded-xl border border-line",
        )}
      >
        <div
          ref={mountRef}
          onDoubleClick={toggleFullscreen}
          className="flex h-full w-full items-center justify-center"
        />
        {phase === "loading" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <Spinner />
            <p className="text-xs text-muted">Loading the desktop recording…</p>
          </div>
        )}
        {phase === "error" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 px-6 text-center">
            <IconAlert size={22} className="text-danger" />
            <p className="text-sm text-fg">This recording could not be replayed.</p>
            <p className="max-w-md text-2xs text-muted">{message}</p>
          </div>
        )}
      </div>

      <div
        className={cn(
          "flex items-center gap-2 transition-opacity",
          fullscreen && "bg-black/85 px-4 py-3",
          controlsHidden && "pointer-events-none opacity-0",
        )}
      >
        <PlayerButton label={playing ? "Pause (space)" : "Play (space)"} onClick={toggle} disabled={!ready}>
          {playing ? <PauseGlyph /> : <PlayGlyph />}
        </PlayerButton>
        <PlayerButton label="Back 10 seconds (j)" onClick={() => nudge(-SKIP_MS)} disabled={!ready}>
          <SkipGlyph back />
        </PlayerButton>
        <PlayerButton label="Forward 10 seconds (l)" onClick={() => nudge(SKIP_MS)} disabled={!ready}>
          <SkipGlyph />
        </PlayerButton>

        <Scrubber
          position={position}
          duration={duration}
          markers={markers}
          disabled={!ready}
          onSeek={seekTo}
        />

        <span className={cn("shrink-0 font-mono text-2xs tabular-nums", fullscreen ? "text-white/80" : "text-muted")}>
          {fmtClock(position)} / {fmtClock(duration)}
        </span>

        <FullscreenButton fullscreen={fullscreen} onToggle={toggleFullscreen} />
      </div>

      {scrubbing && !fullscreen && <p className="text-2xs text-faint">Seeking…</p>}
    </div>
  );
});
