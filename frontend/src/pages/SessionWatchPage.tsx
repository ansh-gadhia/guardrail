import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui";
import { toast } from "@/components/Toast";
import { IconMonitor, IconMaximize, IconMinimize, IconRefresh } from "@/components/icons";
import { DesktopPlayer } from "@/components/DesktopPlayer";

/* SessionWatchPage is for looking at somebody else's live session.
 *
 * It is a separate page from SessionViewPage, not a mode of it, because the two
 * differ in the one way that matters: this one cannot touch the session. The
 * view page carries Terminate — right there, next to the frame — and a
 * supervisor who opened a colleague's session to look at it and pressed the only
 * button on the page would end that colleague's work mid-command. There is no
 * Terminate here at all. Leaving is navigation, and says so.
 *
 * The stream is read-only server-side too: the gateway discards anything an
 * observer sends. The page not sending is the near side of the same rule, so a
 * watcher never sees their own keystrokes echo and think they landed.
 */
export function SessionWatchPage() {
  const { id = "" } = useParams();
  const [params] = useSearchParams();
  const name = params.get("name") || "session";
  const who = params.get("who") || "";
  const navigate = useNavigate();
  const [frameKey, setFrameKey] = useState(0);
  const [full, setFull] = useState(false);
  const stageRef = useRef<HTMLDivElement>(null);

  // A watch grant is minted per open: it is scoped to this session, expires, and
  // the permission check and audit happen when it is issued. Reopening re-checks
  // and re-audits, which is why the Reconnect button mints a new one rather than
  // reusing this.
  const grant = useMutation({
    mutationFn: async () =>
      (await api.post<{ console_url: string; protocol: string }>(`/sessions/${id}/observe`, {})).data,
    onError: () => toast.error("Could not start watching this session"),
  });
  const start = grant.mutate;
  useEffect(() => {
    if (id) start();
  }, [id, frameKey, start]);

  // The session's own status, so a watcher is told when it ends rather than
  // left looking at a frozen screen wondering whether it is still live.
  const status = useQuery<{ status: string; protocol: string }>({
    queryKey: ["session", id],
    queryFn: async () => (await api.get<{ status: string; protocol: string }>(`/sessions/${id}`)).data,
    refetchInterval: 4000,
    // As on the operator's own view: a watcher who switches tabs must still be
    // told when the session they are watching ends.
    refetchIntervalInBackground: true,
    enabled: !!id,
    retry: false,
  });
  const ended = !!status.data && status.data.status !== "active";
  // Which renderer. Taken from the grant when it is there and the session record
  // otherwise, so the choice is made from what the server said rather than from
  // a guess at the device.
  const proto = grant.data?.protocol || status.data?.protocol;
  const isDesktop = proto === "rdp" || proto === "vnc";

  // The browser's own fullscreen, not a fixed-position imitation. Escape and the
  // F11 chrome leave fullscreen without telling the app, so the state is read
  // from the document rather than from our click — otherwise the button keeps
  // saying "Exit full screen" and does nothing.
  useEffect(() => {
    const onChange = () => setFull(document.fullscreenElement === stageRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);
  const toggleFull = () => {
    const el = stageRef.current;
    if (!el) return;
    if (document.fullscreenElement === el) void document.exitFullscreen();
    else void el.requestFullscreen().catch(() => setFull(false));
  };

  return (
    /* An explicit viewport height, like the operator's own session view. h-full
       resolves against the parent, and the app shell above this does not carry a
       height — so the viewer rendered as a box the size of its content rather
       than filling the screen. */
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <IconMonitor size={18} className="shrink-0 text-accent" />
            <h1 className="truncate text-lg font-semibold text-fg">Watching {name}</h1>
            <Badge tone="info">read-only</Badge>
            {ended && <Badge tone="warn">session ended</Badge>}
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {who ? `${who} is working in this session. ` : ""}
            You can see it, but nothing you type is sent — they are not interrupted, and they are not
            disconnected when you leave.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-subtle" onClick={() => setFrameKey((k) => k + 1)} title="Reopen the stream">
            <IconRefresh size={15} /> Reconnect
          </button>
          <button className="btn-subtle" onClick={toggleFull} title={full ? "Exit full screen" : "Full screen"}>
            {full ? <IconMinimize size={15} /> : <IconMaximize size={15} />}
          </button>
          {/* The only way out, and it is navigation. Stopping watching does not
              touch the session: that is the entire difference between this page
              and the one the operator uses. */}
          <button className="btn-primary" onClick={() => navigate("/sessions")}>
            Stop watching
          </button>
        </div>
      </div>

      <div
        ref={stageRef}
        className={
          "relative min-h-0 flex-1 overflow-hidden border border-line bg-surface-1 shadow-sm " +
          // Fullscreen is edge to edge: a rounded card floating on a black screen
          // is not what anyone means by it.
          (full ? "rounded-none border-0" : "rounded-xl")
        }
      >
        {ended ? (
          <div className="grid h-full place-items-center p-6 text-center">
            <div>
              <p className="text-sm font-medium text-fg">This session has ended.</p>
              <p className="mt-1 text-xs text-muted">
                There is nothing more to watch. If it was recorded, the recording is the way to review it.
              </p>
              <button className="btn-subtle mt-3" onClick={() => navigate("/sessions")}>
                Back to sessions
              </button>
            </div>
          </div>
        ) : grant.data ? (
          isDesktop ? (
            /* A desktop is drawing instructions decoded onto a canvas by this
               app, so there is no server page to frame — the same renderer the
               operator uses, with its input unbound. Framing the gateway's JSON
               description of the session instead is exactly how "Open" used to
               show a raw response body. */
            <DesktopPlayer key={frameKey} sessionId={id} readOnly watermark={who ? `watching · ${who}` : undefined} />
          ) : (
            <iframe
              key={frameKey}
              title={`Watching ${name}`}
              src={grant.data.console_url}
              className="h-full w-full border-0"
              /* No allow-forms and no allow-popups: this frame only renders
                 output somebody else is producing. */
              sandbox="allow-scripts allow-same-origin"
            />
          )
        ) : (
          <div className="grid h-full place-items-center p-6 text-center text-sm text-muted">
            {grant.isPending ? "Starting the stream…" : "Could not start watching this session."}
          </div>
        )}
      </div>
    </div>
  );
}
