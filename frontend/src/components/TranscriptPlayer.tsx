import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Spinner, cn } from "@/components/ui";
import { IconSearch, IconAlert, IconChevronUp, IconChevronDown, IconCommand } from "@/components/icons";
import { renderTranscript } from "@/lib/terminalText";
import type { PlayerHandle } from "@/components/player/PlayerChrome";

/* The SSH transcript viewer.

   A terminal session is stored as the bytes the device printed, plus a manifest
   indexing them by time. It is not video, and it should not pretend to be: the
   thing that makes a terminal recording worth having is that it is text, so this
   renders it as text you can search. Finding "shutdown" across an hour of session
   is a keystroke; finding it in a pixel replay means watching an hour.

   Only device output was captured, never keystrokes — see the recorder. The echo
   already shows what was typed at a prompt, while a password prompt echoes
   nothing, so this reproduces the session without harvesting secrets. */

interface Chunk {
  offset_ms: number;
  len: number;
}

interface TranscriptManifest {
  version: number;
  cols: number;
  rows: number;
  chunks: Chunk[];
  // Size changes during the session, so the bytes are laid out at the width the
  // device wrote them for. Absent from transcripts recorded before 1.8.
  resizes?: { offset_ms: number; at: number; cols: number; rows: number }[];
  initial_cols?: number;
  initial_rows?: number;
  // The transcript hit its byte cap. A reviewer must be told, or they will read a
  // partial session as a complete one.
  truncated?: boolean;
}

function hhmmss(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`;
}

/* The lines are shown as the terminal showed them: not wrapped. A terminal
   lays output out in columns padded with spaces — `ls`, `ip addr`, a routing
   table — and re-wrapping those lines to the width of this panel scattered the
   columns down the page with gaps between them. Long lines scroll sideways
   instead; wrapping is a click away for someone reading a long one. */
export const TranscriptPlayer = forwardRef<
  PlayerHandle,
  { sessionId: string; onTimeChange?: (ms: number) => void }
>(function TranscriptPlayer({ sessionId, onTimeChange }, ref) {
  const [manifest, setManifest] = useState<TranscriptManifest | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [wrap, setWrap] = useState(false);
  // The line the timeline last jumped to, highlighted until the next jump.
  const [focus, setFocus] = useState<number | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const [m, t] = await Promise.all([
          // The transcript's own index, not /recording/manifest — that one is the
          // screencast's, and a terminal session may now carry both. The server
          // falls back to the old shared kind for transcripts recorded before
          // they were told apart.
          api.get<TranscriptManifest>(`/sessions/${sessionId}/recording/transcript/manifest`),
          // Fetched as bytes, not as a JSON/text response: the transcript is
          // whatever the device emitted, and axios must not try to parse it.
          api.get(`/sessions/${sessionId}/recording/transcript`, { responseType: "arraybuffer" }),
        ]);
        if (cancelled) return;
        setManifest(m.data);
        setBytes(new Uint8Array(t.data as ArrayBuffer));
      } catch {
        if (!cancelled) setError("The transcript could not be loaded.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const rendered = useMemo(
    () => (bytes && manifest ? renderTranscript(bytes, manifest) : { lines: [], chunkLine: [] }),
    [bytes, manifest],
  );
  const lines = rendered.lines;

  // Which lines match, in order. Case-insensitive: nobody searching a transcript
  // for an incident knows the case the device chose to print it in.
  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const out: number[] = [];
    lines.forEach((l, i) => l.text.toLowerCase().includes(q) && out.push(i));
    return out;
  }, [lines, query]);

  useEffect(() => setActive(0), [query]);

  const reveal = (i: number) =>
    bodyRef.current?.querySelector<HTMLElement>(`[data-line="${i}"]`)?.scrollIntoView({
      block: "center",
      behavior: "smooth",
    });

  // Keep the current match on screen as the reviewer steps through.
  useEffect(() => {
    if (matches.length) reveal(matches[active]);
  }, [active, matches]);

  // The timeline jumps here. A moment is turned into a line through the index —
  // the chunk the device was printing at that moment, and the line the cursor
  // was on once it had — and then, because the timeline's clock and the
  // recorder's start a moment apart, onto the nearest line that carries the
  // command itself.
  useImperativeHandle(
    ref,
    () => ({
      seekTo(ms: number, hint?: string) {
        if (!manifest || !lines.length) return;
        const chunks = manifest.chunks ?? [];
        let c = -1;
        for (let i = 0; i < chunks.length && chunks[i].offset_ms <= ms + 250; i++) c = i;
        let target = c < 0 ? 0 : (rendered.chunkLine[c] ?? 0);
        const needle = hint?.split("\n")[0].trim();
        if (needle) {
          const near = (i: number) => i >= 0 && i < lines.length && lines[i].text.includes(needle);
          for (let d = 0; d <= 60; d++) {
            if (near(target - d)) {
              target -= d;
              break;
            }
            if (d <= 5 && near(target + d)) {
              target += d;
              break;
            }
          }
        }
        setFocus(target);
        reveal(target);
        onTimeChange?.(ms);
      },
    }),
    [manifest, lines, rendered, onTimeChange],
  );

  const duration = manifest?.chunks?.length ? manifest.chunks[manifest.chunks.length - 1].offset_ms : 0;
  const step = (d: number) => matches.length && setActive((a) => (a + d + matches.length) % matches.length);

  if (loading) {
    return (
      <div className="flex h-72 items-center justify-center rounded-xl border border-line bg-surface-2/40">
        <Spinner />
      </div>
    );
  }
  if (error || !manifest) {
    return (
      <div className="flex h-72 flex-col items-center justify-center gap-2 rounded-xl border border-line bg-surface-2/40 px-6 text-center">
        <IconCommand size={22} className="text-faint" />
        <p className="text-sm text-muted">{error ?? "No transcript was captured."}</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-2/40">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-3 py-2">
        <div className="relative min-w-0 flex-1">
          <IconSearch size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-faint" />
          <input
            className="input h-8 w-full pl-7 text-xs"
            placeholder="Search the transcript…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                step(e.shiftKey ? -1 : 1);
              }
            }}
          />
        </div>
        {query.trim() !== "" && (
          <div className="flex shrink-0 items-center gap-1">
            <span className="text-2xs tabular-nums text-muted">
              {matches.length ? `${active + 1} of ${matches.length}` : "no matches"}
            </span>
            <button
              className="btn-ghost h-7 px-1.5"
              disabled={!matches.length}
              aria-label="Previous match"
              onClick={() => step(-1)}
            >
              <IconChevronUp size={14} />
            </button>
            <button
              className="btn-ghost h-7 px-1.5"
              disabled={!matches.length}
              aria-label="Next match"
              onClick={() => step(1)}
            >
              <IconChevronDown size={14} />
            </button>
          </div>
        )}
        <button
          type="button"
          className={cn("btn-ghost h-7 shrink-0 px-2 text-2xs", wrap && "text-accent")}
          aria-pressed={wrap}
          title={wrap ? "Show lines as the terminal did, scrolling sideways" : "Wrap long lines to the panel"}
          onClick={() => setWrap((w) => !w)}
        >
          Wrap
        </button>
        <span className="shrink-0 text-2xs text-faint">
          {lines.length.toLocaleString()} lines · {hhmmss(duration)}
        </span>
      </div>

      {manifest.truncated && (
        <p className="flex items-start gap-1.5 border-b border-line bg-warn/10 px-3 py-2 text-2xs text-warn">
          <IconAlert size={13} className="mt-px shrink-0" />
          <span>
            This session printed more output than the transcript cap allows, so the end is missing. What is shown is
            the beginning of the session, not all of it.
          </span>
        </p>
      )}

      <div ref={bodyRef} className="h-72 overflow-auto bg-[#0b0e14] p-3 font-mono text-xs leading-[1.4]">
        <div className={wrap ? undefined : "w-max min-w-full"}>
          {lines.map((l, i) =>
            l.marker ? (
              <div
                key={i}
                data-line={i}
                className="my-1 flex select-none items-center gap-2 pl-10 text-2xs italic text-[#5c6a80]"
              >
                <span className="h-px w-4 bg-[#2a3344]" />
                {l.marker === "fullscreen-start"
                  ? "full-screen program — what it showed"
                  : "end of full-screen program"}
                <span className="h-px w-4 bg-[#2a3344]" />
              </div>
            ) : (
              <div
                key={i}
                data-line={i}
                className={cn(
                  wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre",
                  focus === i
                    ? "bg-accent/25"
                    : matches.length && matches[active] === i
                      ? "bg-accent/25"
                      : query.trim() && matches.includes(i) && "bg-accent/10",
                )}
              >
                <span className="select-none pr-3 text-[#3d4657]">{String(i + 1).padStart(4, " ")}</span>
                <span className="text-[#c3cddb]">{l.text || " "}</span>
              </div>
            ),
          )}
        </div>
      </div>
    </div>
  );
});
