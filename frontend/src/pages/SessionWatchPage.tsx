import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui";
import { toast } from "@/components/Toast";
import { IconMonitor, IconMaximize, IconMinimize, IconRefresh } from "@/components/icons";

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
  const shellRef = useRef<HTMLDivElement>(null);

  // A watch grant is minted per open: it is scoped to this session, expires, and
  // the permission check and audit happen when it is issued. Reopening re-checks
  // and re-audits, which is why the Reconnect button mints a new one rather than
  // reusing this.
  const grant = useMutation({
    mutationFn: async () => (await api.post<{ console_url: string }>(`/sessions/${id}/observe`, {})).data,
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
    enabled: !!id,
    retry: false,
  });
  const ended = !!status.data && status.data.status !== "active";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && full) setFull(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [full]);

  return (
    <div className="flex h-full flex-col gap-3">
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
          <button className="btn-subtle" onClick={() => setFull((f) => !f)} title={full ? "Exit full screen" : "Full screen"}>
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
        ref={shellRef}
        className={
          full
            ? "fixed inset-0 z-50 bg-surface-1"
            : "relative min-h-0 flex-1 overflow-hidden rounded-xl border border-line bg-surface-1"
        }
      >
        {full && (
          <button className="btn-subtle absolute right-3 top-3 z-10" onClick={() => setFull(false)}>
            <IconMinimize size={15} /> Exit full screen
          </button>
        )}
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
          <iframe
            key={frameKey}
            title={`Watching ${name}`}
            src={grant.data.console_url}
            className="h-full w-full border-0"
            /* No allow-forms and no allow-popups: this frame only renders a
               terminal somebody else is typing into. */
            sandbox="allow-scripts allow-same-origin"
          />
        ) : (
          <div className="grid h-full place-items-center p-6 text-center text-sm text-muted">
            {grant.isPending ? "Starting the stream…" : "Could not start watching this session."}
          </div>
        )}
      </div>
    </div>
  );
}
