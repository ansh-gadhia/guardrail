import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, getAccessToken } from "@/lib/api";
import { Button, Badge, cn } from "@/components/ui";
import { toast } from "@/components/Toast";
import { IconTrash, IconMaximize, IconMinimize, IconRefresh } from "@/components/icons";
import { DesktopPlayer } from "@/components/DesktopPlayer";

// SessionViewPage embeds the brokered device UI in a same-origin iframe. The
// credential was injected server-side at connect time and is never exposed here;
// this page only carries the session cookie the proxy validates.
//
// The attribution watermark is not drawn over the iframe. It is injected into the
// session document by the gateway, so that it is present however the session is
// reached and — in browser-isolation mode — is burned into the recorded frames.
// An overlay rendered by this shell would be neither.
//
// A desktop is the exception, and has to be: it arrives as drawing instructions
// on a canvas, with no document to inject into and no compositing in guacd. So
// the desktop's watermark is passed to the player and drawn over the canvas,
// where it is a deterrent rather than a control. See DesktopPlayer.
export function SessionViewPage() {
  const { id = "" } = useParams();
  const [params] = useSearchParams();
  const name = params.get("name") || "session";
  const navigate = useNavigate();
  const proxyUrl = `/proxy/${id}/`;

  const terminate = useMutation({
    mutationFn: async () => api.post(`/sessions/${id}/terminate`, {}),
    onSuccess: () => toast.success("Session ended"),
    onSettled: () => navigate("/sessions"),
  });

  // Watch the authoritative session status. If it stops being active — someone
  // else terminated it, or its window expired — the proxy is already refusing
  // requests server-side, so drop a blocking overlay instead of showing a dead
  // (or silently 410-ing) iframe.
  const status = useQuery<{ status: string; protocol: string; watermark?: string }>({
    queryKey: ["session", id],
    queryFn: async () =>
      (await api.get<{ status: string; protocol: string; watermark?: string }>(`/sessions/${id}`)).data,
    refetchInterval: 4000,
    enabled: !!id,
    retry: false,
  });
  const ended = !!status.data && status.data.status !== "active";
  // How the session is rendered follows from its protocol. A desktop is drawing
  // instructions decoded onto a canvas in this app; everything else is the
  // gateway's own page in an iframe. The session says which — asking the device
  // would be asking a record that may have been edited since.
  //
  // Telnet used to be in this list, because it was brokered through guacd and so
  // arrived as pixels like a desktop. It is now served natively as text, the same
  // as SSH, and takes the iframe branch with it: the gateway serves an xterm
  // console at the session root.
  const isDesktop = status.data?.protocol === "rdp" || status.data?.protocol === "vnc";

  // Close the tab, close the session. `pagehide` fires on a real unload (tab
  // close, reload, external navigation) but NOT on in-app React Router
  // navigation, so leaving via "End session" or the sidebar doesn't double-fire.
  // `keepalive` lets the POST outlive the page, and unlike sendBeacon it can
  // carry the bearer token the endpoint requires.
  useEffect(() => {
    const onHide = () => {
      const token = getAccessToken();
      try {
        void fetch(`/api/v1/sessions/${id}/terminate`, {
          method: "POST",
          keepalive: true,
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
      } catch {
        /* best effort — nothing more we can do during unload */
      }
    };
    window.addEventListener("pagehide", onHide);
    return () => window.removeEventListener("pagehide", onHide);
  }, [id]);

  // Full screen targets the session frame, not the window: the operator wants the
  // device's screen bigger, not the console's chrome. The desktop player already
  // follows its container via a ResizeObserver, and the iframe fills it, so both
  // simply grow.
  // Reconnect. The gateways already heal what they can on their own — a dropped
  // WebSocket re-attaches itself, and a device that hung up gets an offer inside
  // the terminal — but both of those only appear once something has visibly
  // broken. This is the case they miss: a session that is not disconnected and
  // not working either, where the operator can see it is wrong and has nothing to
  // press. Remounting the frame is a real reconnect for every protocol, because
  // it opens a new session socket, and the gateway dials the device again if its
  // connection is gone.
  const [frameKey, setFrameKey] = useState(0);
  const reconnect = () => setFrameKey((k) => k + 1);

  const stageRef = useRef<HTMLDivElement>(null);
  const [isFull, setIsFull] = useState(false);
  useEffect(() => {
    // Track the browser's own state rather than our click: Escape and the F11
    // chrome exit fullscreen without telling us, and a button still reading "Exit
    // full screen" after that does nothing when pressed.
    const onChange = () => setIsFull(document.fullscreenElement === stageRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);
  const toggleFull = () => {
    const el = stageRef.current;
    if (!el) return;
    if (document.fullscreenElement === el) void document.exitFullscreen();
    else void el.requestFullscreen().catch(() => setIsFull(false));
  };

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="truncate font-display text-lg font-semibold tracking-tight text-fg">{name}</h1>
            {ended ? <Badge tone="danger">ended</Badge> : <Badge tone="success" dot>live</Badge>}
          </div>
          <p className="font-mono text-xs text-faint">session {id.slice(0, 8)}…</p>
        </div>
        {/* No "open in new tab" affordance: a session opened outside this shell
            loses the status polling and the close-tab-ends-session handler, and
            the platform should not ship a one-click way to shed them. */}
        <div className="flex items-center gap-2">
          {/* Offered only while the session can actually be used. */}
          {!ended && (
            <Button
              variant="ghost"
              icon={IconRefresh}
              onClick={reconnect}
              title="Reopen the connection to this device. The session, and its recording, continue."
            >
              Reconnect
            </Button>
          )}
          {!ended && (
            <Button
              variant="ghost"
              icon={isFull ? IconMinimize : IconMaximize}
              onClick={toggleFull}
              title={isFull ? "Exit full screen" : "Full screen"}
            >
              {isFull ? "Exit full screen" : "Full screen"}
            </Button>
          )}
          <Button variant="danger" icon={IconTrash} loading={terminate.isPending} onClick={() => terminate.mutate()}>
            End session
          </Button>
        </div>
      </div>
      <div
        ref={stageRef}
        className={cn(
          "relative flex-1 overflow-hidden border border-line shadow-sm",
          // Fullscreen means edge to edge: a rounded, inset card floating on a
          // black screen is not what anyone means by full screen.
          isFull ? "rounded-none border-0" : "rounded-xl",
          isDesktop ? "bg-[#0b0e14]" : "bg-white",
        )}
      >
        {/* key is the reconnect: changing it remounts the child, which tears the
            old socket down and opens a new one. */}
        {status.isLoading ? null : isDesktop ? (
          <DesktopPlayer key={frameKey} sessionId={id} watermark={status.data?.watermark} />
        ) : (
          <iframe
            key={frameKey}
            title={name}
            src={proxyUrl}
            className="h-full w-full"
            // The device UI needs scripts/forms/popups of its own to function.
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-downloads"
          />
        )}
        {ended && (
          <div className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 bg-surface/95 text-center backdrop-blur-sm">
            <span className="grid h-12 w-12 place-items-center rounded-2xl bg-danger/10 text-danger">
              <IconTrash size={24} />
            </span>
            <div className="font-display text-lg font-semibold text-fg">Session ended</div>
            <p className="max-w-xs text-sm text-muted">
              This access session is no longer active. Any further activity through it is blocked.
            </p>
            <Button variant="primary" onClick={() => navigate("/sessions")}>
              Back to sessions
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

