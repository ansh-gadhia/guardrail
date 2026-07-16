import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Spinner, cn } from "@/components/ui";
import { IconSearch, IconAlert, IconChevronUp, IconChevronDown, IconCommand } from "@/components/icons";

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
  // The transcript hit its byte cap. A reviewer must be told, or they will read a
  // partial session as a complete one.
  truncated?: boolean;
}

/* renderTerminal turns raw terminal output into the lines a person saw.

   The bytes are not plain text: they carry the escape sequences that colour the
   prompt, redraw progress bars and move the cursor. Dumping them raw shows
   "ESC[0;32m" noise around every word and makes the transcript unsearchable,
   which defeats the point of keeping text. So the control layer is interpreted
   just enough to recover the visible characters:

   - CSI (ESC[...) and OSC (ESC]...) sequences are dropped — colour and title
     changes leave no character behind.
   - \r returns to the start of the line, so what follows overwrites it. This is
     what a progress bar or a spinner does; without it a one-line download meter
     unrolls into hundreds of lines.
   - \b erases the character before it, which is how a terminal shows a
     correction.

   This is not a terminal emulator: full cursor addressing (a curses UI like
   `top`) will not reconstruct perfectly. It reconstructs what a scrolling shell
   session prints, which is what an SSH audit trail is nearly always made of. */
export function renderTerminal(raw: string): string[] {
  const lines: string[] = [];
  let line = "";
  let col = 0;

  const put = (ch: string) => {
    // Overwrite at the cursor rather than always appending: after a \r the
    // cursor is back at column 0 and the old text is still there.
    if (col < line.length) line = line.slice(0, col) + ch + line.slice(col + 1);
    else line += ch;
    col++;
  };

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];

    if (ch === "\x1b") {
      const next = raw[i + 1];
      if (next === "[") {
        // CSI: parameters, then a final byte in @-~.
        let j = i + 2;
        while (j < raw.length && !/[@-~]/.test(raw[j])) j++;
        i = j;
        continue;
      }
      if (next === "]") {
        // OSC: runs until BEL or ESC\.
        let j = i + 2;
        while (j < raw.length && raw[j] !== "\x07" && !(raw[j] === "\x1b" && raw[j + 1] === "\\")) j++;
        i = raw[j] === "\x1b" ? j + 1 : j;
        continue;
      }
      // Any other two-byte escape (charset selection and friends).
      i++;
      continue;
    }

    if (ch === "\n") {
      lines.push(line);
      line = "";
      col = 0;
      continue;
    }
    if (ch === "\r") {
      col = 0;
      continue;
    }
    if (ch === "\b") {
      if (col > 0) col--;
      continue;
    }
    if (ch === "\t") {
      // Tabs land on 8-column stops; spaces keep the column arithmetic honest.
      const stop = 8 - (col % 8);
      for (let k = 0; k < stop; k++) put(" ");
      continue;
    }
    // Drop the remaining C0 controls (BEL and friends): they are events, not
    // characters, and rendering them as glyphs is noise.
    if (ch < " " && ch !== " ") continue;
    put(ch);
  }
  if (line.length) lines.push(line);
  return lines;
}

function hhmmss(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`;
}

export function TranscriptPlayer({ sessionId }: { sessionId: string }) {
  const [manifest, setManifest] = useState<TranscriptManifest | null>(null);
  const [text, setText] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const [m, t] = await Promise.all([
          api.get<TranscriptManifest>(`/sessions/${sessionId}/recording/manifest`),
          // Fetched as bytes, not as a JSON/text response: the transcript is
          // whatever the device emitted, and axios must not try to parse it.
          api.get(`/sessions/${sessionId}/recording/transcript`, { responseType: "arraybuffer" }),
        ]);
        if (cancelled) return;
        setManifest(m.data);
        // A device may emit bytes that are not valid UTF-8. Decoding leniently
        // replaces them rather than throwing away the whole transcript.
        setText(new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(t.data as ArrayBuffer)));
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

  const lines = useMemo(() => renderTerminal(text), [text]);

  // Which lines match, in order. Case-insensitive: nobody searching a transcript
  // for an incident knows the case the device chose to print it in.
  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const out: number[] = [];
    lines.forEach((l, i) => l.toLowerCase().includes(q) && out.push(i));
    return out;
  }, [lines, query]);

  useEffect(() => setActive(0), [query]);

  // Keep the current match on screen as the reviewer steps through.
  useEffect(() => {
    if (!matches.length) return;
    bodyRef.current?.querySelector<HTMLElement>(`[data-line="${matches[active]}"]`)?.scrollIntoView({
      block: "center",
      behavior: "smooth",
    });
  }, [active, matches]);

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

      <div ref={bodyRef} className="h-72 overflow-auto bg-[#0b0e14] p-3 font-mono text-xs leading-[1.45]">
        {lines.map((l, i) => (
          <div
            key={i}
            data-line={i}
            className={cn(
              "whitespace-pre-wrap break-all",
              matches.length && matches[active] === i ? "bg-accent/25" : query.trim() && matches.includes(i) && "bg-accent/10",
            )}
          >
            <span className="select-none pr-3 text-[#3d4657]">{String(i + 1).padStart(4, " ")}</span>
            <span className="text-[#c3cddb]">{l || " "}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
