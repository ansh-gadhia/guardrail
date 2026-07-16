import Guacamole from "guacamole-common-js";

// A one-shot Guacamole tunnel that replays an already-downloaded recording blob.
//
// Why this exists: guacamole-common-js 1.5.0 — the newest published version —
// cannot play a recording from a Blob. Its SessionRecording(Blob) constructor
// calls parseBlob(recordingBlob, …) but never assigns recordingBlob = source, so
// it parses `undefined` and throws. The Blob branch is simply broken upstream.
//
// The TUNNEL branch, however, works: it reads instructions from a tunnel and
// rebuilds its own seekable blob from them. So we hand SessionRecording a tunnel
// instead of a blob. This tunnel does the one thing that branch needs — parse the
// bytes we already fetched and emit each instruction — using the library's own
// Guacamole.Parser, so the format handling is exactly the library's.
//
// SessionRecording duck-types the tunnel (it only ever touches oninstruction,
// onerror, onstatechange and connect/disconnect), which is why a minimal object
// cast to Guacamole.Tunnel is enough and a full abstract-class subclass is not.

// Feed the parser in bounded slices, yielding between them. A long RDP session is
// tens of MB of instructions; one synchronous receive() of the whole string would
// freeze the tab while it parsed. The parser buffers partial instructions across
// calls, so slicing the text at arbitrary character boundaries is safe.
const CHUNK_CHARS = 200_000;

export function blobReplayTunnel(blob: Blob): Guacamole.Tunnel {
  const parser = new Guacamole.Parser();
  const State = Guacamole.Tunnel.State;

  const tunnel = {
    state: State.CONNECTING as Guacamole.Tunnel.State,
    uuid: null as string | null,
    receiveTimeout: 15000,
    unstableThreshold: 1500,
    oninstruction: null as null | ((opcode: string, args: unknown[]) => void),
    onstatechange: null as null | ((state: Guacamole.Tunnel.State) => void),
    onerror: null as null | ((status: { code?: number; message: string }) => void),
    onuuid: null as null | ((uuid: string) => void),

    isConnected(): boolean {
      return this.state === State.OPEN;
    },
    sendMessage(): void {
      // A recording is one-way. There is nothing to send back to a file.
    },

    connect(): void {
      this.state = State.OPEN;
      this.onstatechange?.(this.state);

      parser.oninstruction = (opcode, args) => this.oninstruction?.(opcode, args as unknown[]);

      const close = () => {
        this.state = State.CLOSED;
        this.onstatechange?.(this.state);
      };
      const fail = (message: string) => {
        this.onerror?.({ message });
        close();
      };

      void blob
        .text()
        .then(async (text) => {
          try {
            for (let i = 0; i < text.length; i += CHUNK_CHARS) {
              parser.receive(text.slice(i, i + CHUNK_CHARS));
              // Yield so a large recording paints progressively and the tab stays
              // responsive; SessionRecording fires onprogress as frames land.
              if (i + CHUNK_CHARS < text.length) await new Promise((r) => setTimeout(r, 0));
            }
          } catch (e) {
            fail(e instanceof Error ? e.message : "The recording could not be parsed.");
            return;
          }
          // Closing the tunnel with no error is how SessionRecording learns the
          // recording is fully loaded and fires onload.
          close();
        })
        .catch(() => fail("The recording could not be read from the browser."));
    },

    disconnect(): void {
      this.state = State.CLOSED;
      this.onstatechange?.(this.state);
    },
  };

  // SessionRecording only duck-types the tunnel; the cast bridges that to the
  // abstract Tunnel type without implementing members it never calls.
  return tunnel as unknown as Guacamole.Tunnel;
}
