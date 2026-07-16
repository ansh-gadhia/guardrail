import { useEffect, useRef, useState } from "react";
import Guacamole from "guacamole-common-js";
import { Spinner } from "@/components/ui";
import { toast } from "@/components/Toast";
import { IconAlert, IconClipboard, IconMonitor } from "@/components/icons";

/* The RDP/VNC desktop viewer.

   guacd renders the device's desktop into a stream of drawing instructions; this
   decodes them onto a canvas and sends mouse and keyboard back. The device
   credential never reaches this page — guacd authenticated to the device
   server-side during the connect handshake, and what arrives here is pixels and
   nothing else. That is the same guarantee browser isolation gives a web UI.

   The WebSocket carries no token of its own: it is the session's HttpOnly cookie,
   scoped to /proxy/<sid>/, that authenticates it. So this cannot be opened from
   another origin, and the token is never readable by script.

   The attribution watermark is drawn here, over the canvas. This is the one
   surface where it has to be: the other gateways stamp it into the document they
   serve, but a desktop arrives as drawing instructions and guacd composites
   nothing, so there is no document to stamp. Drawn here it is a deterrent and not
   a control — it is in the operator's DOM and anyone with devtools can delete it,
   and because guacd writes the recording server-side it is not in the recorded
   frames either. What actually holds a desktop session accountable is that
   recording. The watermark's job is to make an operator aware they are attributed
   while they work, which it does. */

type Status = "connecting" | "connected" | "closed" | "error";

// Guacamole's numeric states. 3 = CONNECTED; 4 and 5 are the two ways it ends.
const STATE_CONNECTED = 3;
const STATE_DISCONNECTING = 4;
const STATE_DISCONNECTED = 5;

export function DesktopPlayer({
  sessionId,
  watermark,
  terminal,
  onEnded,
}: {
  sessionId: string;
  watermark?: string;
  // Whether guacd is drawing a terminal (telnet) rather than a graphical desktop
  // (RDP/VNC). It changes only one thing the operator sees: how a paste lands.
  // guacd's terminal takes an inbound clipboard on Ctrl+Shift+V; a desktop's
  // remote OS takes it on its own Ctrl+V.
  terminal?: boolean;
  onEnded?: () => void;
}) {
  const mountRef = useRef<HTMLDivElement>(null);
  // Held so the paste control can open a clipboard stream on the live client
  // without the effect re-running. Null until connected, and again once torn down.
  const clientRef = useRef<Guacamole.Client | null>(null);
  const [status, setStatus] = useState<Status>("connecting");
  const [message, setMessage] = useState<string>("");

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    // The same sentinel path the gateway mounts the socket on, under the session
    // prefix so the cookie is sent.
    const url = `${scheme}://${window.location.host}/proxy/${sessionId}/__ws__`;

    const tunnel = new Guacamole.WebSocketTunnel(url);
    const client = new Guacamole.Client(tunnel);
    clientRef.current = client;
    const display = client.getDisplay();
    mount.appendChild(display.getElement());

    client.onstatechange = (state: number) => {
      if (state === STATE_CONNECTED) setStatus("connected");
      if (state === STATE_DISCONNECTED || state === STATE_DISCONNECTING) {
        // Never downgrade an error to "ended". guacd reports a failure as an
        // `error` instruction and THEN drops the connection, so onerror fires
        // first and this fires a moment later — and it used to overwrite it. The
        // operator was shown "The desktop session has ended." for every failure
        // guacd could have explained: wrong password, host unreachable, refused
        // certificate, NLA demanded and no credential to offer. The one sentence
        // that said why was replaced, a beat later, by the one that says nothing.
        setStatus((s) => (s === "error" ? s : "closed"));
        onEnded?.();
      }
    };
    // guacd's own words for why a desktop failed — wrong password, host
    // unreachable, certificate refused. Passed through rather than replaced with
    // a generic failure: it is the operator's only clue, and it never names a
    // credential.
    client.onerror = (e: { message?: string }) => {
      setMessage(e?.message || "The desktop connection failed.");
      setStatus("error");
    };
    tunnel.onerror = (e: { message?: string }) => {
      setMessage(e?.message || "The connection to the session was lost.");
      setStatus("error");
    };

    client.connect("");

    // Input. Guacamole 1.5 moved Mouse to an event-target API, so handlers
    // attach with onEach rather than the onmousedown properties older examples
    // (and older Guacamole) use.
    //
    // showCursor(false) hides the display's software cursor because the device
    // draws its own. Skipping it leaves two cursors on screen, one of them
    // always slightly behind.
    const mouse = new Guacamole.Mouse(display.getElement());
    mouse.onEach(["mousedown", "mouseup", "mousemove"], () => {
      display.showCursor(false);
      // The second argument is not optional in practice, it just looks it.
      // Guacamole.Mouse reports where the pointer is on the *page*, in CSS
      // pixels; the device thinks in its own pixels; and fit() below puts a
      // scale factor between the two. sendMouseState defaults applyDisplayScale
      // to false, so without this every click was delivered at the raw CSS
      // offset — on a desktop scaled to 70% of the window, a click landed
      // roughly 1.4x further down and right than where the operator aimed, and
      // the error grew with distance from the top-left corner.
      client.sendMouseState(mouse.currentState, true);
    });

    // Keyboard is bound to the document, not the canvas: a canvas cannot hold
    // focus on its own, and requiring a click before the keyboard works is the
    // kind of papercut that gets reported as "typing doesn't work".
    const keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = (sym: number) => client.sendKeyEvent(1, sym);
    keyboard.onkeyup = (sym: number) => client.sendKeyEvent(0, sym);

    // Follow the container rather than scaling a fixed canvas: a 1280x800 desktop
    // stretched over a 4K screen is unreadable, and unreadable evidence is not
    // evidence.
    //
    // Two separate jobs, and both are needed. rescale() makes whatever the device
    // gives us fit the frame — the only lever available for a VNC server, which
    // mostly cannot resize. pushSize() asks the device for a desktop the size of
    // the frame, which RDP honours (the gateway sets resize-method=display-update
    // for exactly this) and which nothing was doing: the parameter was set,
    // guacd waited to be told a size, and the browser never said. Every desktop
    // ran at the gateway's default geometry and was scaled to fit.
    //
    // Only the observer pushes a size. display.onresize must not, or the device's
    // reply to one resize would trigger the next one forever.
    const rescale = () => {
      const w = mount.clientWidth;
      const h = mount.clientHeight;
      if (!w || !h) return;
      const dw = display.getWidth();
      const dh = display.getHeight();
      if (dw && dh) display.scale(Math.min(w / dw, h / dh));
    };

    let sizeTimer: ReturnType<typeof setTimeout> | undefined;
    let sentW = 0;
    let sentH = 0;
    const pushSize = () => {
      rescale();
      const w = Math.floor(mount.clientWidth);
      const h = Math.floor(mount.clientHeight);
      if (!w || !h || (w === sentW && h === sentH)) return;
      // Debounced because a window drag fires this every frame, and each one is a
      // full desktop reallocation on the device.
      clearTimeout(sizeTimer);
      sizeTimer = setTimeout(() => {
        sentW = w;
        sentH = h;
        try {
          client.sendSize(w, h);
        } catch {
          /* tunnel already closed — the session is ending anyway */
        }
      }, 250);
    };

    const ro = new ResizeObserver(pushSize);
    ro.observe(mount);
    display.onresize = rescale;

    return () => {
      clearTimeout(sizeTimer);
      ro.disconnect();
      keyboard.onkeydown = null;
      keyboard.onkeyup = null;
      mouse.reset();
      try {
        client.disconnect();
      } catch {
        /* already gone — nothing to do */
      }
      if (display.getElement().parentNode === mount) mount.removeChild(display.getElement());
      clientRef.current = null;
    };
  }, [sessionId, onEnded]);

  // Bridge the operator's clipboard into the session. The browser will not let a
  // remote canvas read the system clipboard on its own — nothing types into a
  // desktop or terminal without a deliberate act — so this is that act: read the
  // clipboard on an explicit click (which is what the Clipboard API's permission
  // model requires anyway) and hand the text to guacd over a clipboard stream.
  //
  // Setting guacd's clipboard is only half of a paste; the text still has to be
  // pasted on the far side, and the gesture differs. guacd's terminal takes it on
  // Ctrl+Shift+V (guac_terminal, terminal.c); a graphical desktop's remote OS
  // takes it on its own Ctrl+V. So the toast tells the operator which — a paste
  // button that silently did nothing visible would read as broken.
  const paste = async () => {
    const client = clientRef.current;
    if (!client) return;
    let text: string;
    try {
      text = await navigator.clipboard.readText();
    } catch {
      // Denied, or an insecure origin (the Clipboard API needs HTTPS). There is
      // no server-side fallback: the browser is the only thing that holds the
      // operator's clipboard.
      toast.error("The browser would not share the clipboard. Check the page is on HTTPS and allow clipboard access.");
      return;
    }
    if (!text) {
      toast.info("Your clipboard is empty.");
      return;
    }
    try {
      const stream = client.createClipboardStream("text/plain");
      const writer = new Guacamole.StringWriter(stream);
      writer.sendText(text);
      writer.sendEnd();
    } catch {
      toast.error("The clipboard could not be sent to the session.");
      return;
    }
    toast.success(
      terminal
        ? "Sent to the session. Paste it in the terminal with Ctrl+Shift+V."
        : "Sent to the session. Paste it on the desktop with Ctrl+V.",
    );
  };

  return (
    <div className="relative h-full w-full bg-[#0b0e14]">
      <div ref={mountRef} className="flex h-full w-full items-center justify-center overflow-hidden" />
      {/* Paste control. z-20 so it sits above the watermark layer (z-10), which is
          pointer-events-none and would not block it anyway, but the ordering is
          what makes it clickable and visible. Only while connected: there is no
          clipboard stream to open otherwise. */}
      {status === "connected" && (
        <button
          type="button"
          onClick={paste}
          title={
            terminal
              ? "Send your clipboard to the session, then paste with Ctrl+Shift+V"
              : "Send your clipboard to the session, then paste with Ctrl+V"
          }
          className="absolute right-3 top-3 z-20 flex items-center gap-1.5 rounded-lg border border-white/15 bg-black/50 px-2.5 py-1.5 text-xs text-white/80 backdrop-blur transition hover:bg-black/70 hover:text-white"
        >
          <IconClipboard size={14} />
          Paste
        </button>
      )}
      {/* Only once there are pixels to sit on: a watermark over the "Opening the
          desktop…" spinner attributes nothing.

          pointer-events-none is load-bearing, not styling. This covers the whole
          canvas, and without it the overlay would swallow every click and drag
          before Guacamole.Mouse saw them — a watermark that silently breaks the
          desktop it is attributing. aria-hidden keeps a screen reader from
          reading the same line sixty times; it is decoration over a canvas the
          reader cannot see anyway. */}
      {status === "connected" && watermark && (
        <div aria-hidden className="pointer-events-none absolute inset-0 z-10 select-none overflow-hidden">
          {/* Overhung on every side and rotated, so the tiling has no visible
              start or end that a screenshot could be cropped to exclude. */}
          <div className="absolute -inset-1/3 flex flex-wrap content-center justify-center gap-x-16 gap-y-14 -rotate-[24deg]">
            {Array.from({ length: 72 }).map((_, i) => (
              <span key={i} className="whitespace-nowrap font-mono text-[11px] tracking-wide text-white/25">
                {watermark}
              </span>
            ))}
          </div>
        </div>
      )}
      {status === "connecting" && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-[#0b0e14]">
          <Spinner />
          <p className="text-xs text-muted">Opening the desktop…</p>
        </div>
      )}
      {status === "error" && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[#0b0e14] px-6 text-center">
          <IconAlert size={22} className="text-danger" />
          <p className="text-sm text-fg">The desktop could not be opened.</p>
          <p className="max-w-md text-2xs text-muted">{message}</p>
        </div>
      )}
      {status === "closed" && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[#0b0e14] px-6 text-center">
          <IconMonitor size={22} className="text-faint" />
          <p className="text-sm text-muted">The desktop session has ended.</p>
        </div>
      )}
    </div>
  );
}
