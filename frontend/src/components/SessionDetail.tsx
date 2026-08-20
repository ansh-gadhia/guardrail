import { useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import { absLocal, plausibleDate, relTime, sessionSpan, startedOf } from "@/lib/dates";
import type { Session, SessionEvent, RecordingMeta, AccessRequest } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { Badge, StatusBadge, Modal, EmptyState, ErrorNote, Skeleton, Button, cn } from "@/components/ui";
import { IconFilm, IconTrash, IconAlert, IconDownload } from "@/components/icons";
import { SessionPlayer } from "@/components/SessionPlayer";
import { TranscriptPlayer } from "@/components/TranscriptPlayer";
import { DesktopReplay } from "@/components/DesktopReplay";

/** The replays a recording can offer. One recording may hold more than one. */
type ReplayView = "transcript" | "video" | "desktop";
const VIEW_LABEL: Record<ReplayView, string> = {
  transcript: "Transcript",
  video: "Video",
  desktop: "Desktop replay",
};

/* ---- Session detail -------------------------------------------------------
   Opening a recording shows the whole session in one window: the replay on the
   left, and everything we know about the session on the right — who, what,
   from where, and the activity timeline. They belong together: the video shows
   what happened, and the metadata says who it was and whether they were
   supposed to be there. */
export function SessionDetail({
  session,
  deviceLabel,
  userLabel,
  onClose,
}: {
  session: Session;
  deviceLabel?: string;
  userLabel?: string;
  onClose: () => void;
}) {
  const events = useQuery<SessionEvent[]>({
    queryKey: ["session-events", session.id],
    queryFn: async () => (await api.get<{ data: SessionEvent[] }>(`/sessions/${session.id}/events`, { params: { limit: 500 } })).data.data,
    refetchInterval: session.status === "active" ? 5_000 : false,
  });
  const recording = useQuery<RecordingMeta>({
    queryKey: ["recording", session.id],
    queryFn: async () => (await api.get<RecordingMeta>(`/sessions/${session.id}/recording`)).data,
    // A 404 means this device isn't recorded — a normal answer, not a failure.
    retry: false,
  });

  const started = startedOf(session);
  const notRecorded = recording.isError;
  const hasVideo = recording.data?.has_video ?? false;
  const hasTranscript = recording.data?.has_transcript ?? false;
  const hasDesktop = recording.data?.has_desktop ?? false;

  // Which replays this recording actually holds, in the order they are offered.
  // Transcript first: it loads instantly and is searchable, so it is the better
  // landing view when a session has both.
  const available = useMemo(() => {
    const out: ReplayView[] = [];
    if (hasTranscript) out.push("transcript");
    if (hasVideo) out.push("video");
    if (hasDesktop) out.push("desktop");
    return out;
  }, [hasTranscript, hasVideo, hasDesktop]);
  const [picked, setPicked] = useState<ReplayView | null>(null);
  // Falls back to the first available whenever the pick is not (or no longer)
  // present — the artifacts arrive asynchronously, and a live session gains its
  // video only once it ends.
  const view = picked && available.includes(picked) ? picked : available[0];
  const setView = setPicked;

  const has = useAuth((s) => s.has);
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [delError, setDelError] = useState<string | null>(null);
  const del = useMutation({
    mutationFn: async () => api.delete(`/sessions/${session.id}/recording`),
    onSuccess: () => {
      // The list carries the recorded flag, and the popup is showing something
      // that no longer exists — refresh both and get out.
      qc.invalidateQueries({ queryKey: ["recording", session.id] });
      qc.invalidateQueries({ queryKey: ["sessions"] });
      onClose();
    },
    onError: (e) => setDelError(problemDetail(e, "The recording could not be deleted.")),
  });
  // Offered only when there is something to delete and the operator may do it.
  const canDelete = has("recording:delete") && !notRecorded && !recording.isLoading;

  return (
    <Modal
      title={deviceLabel ?? "Session"}
      icon={IconFilm}
      size="xl"
      onClose={onClose}
      footer={
        <div className="flex w-full items-center justify-between gap-3">
          <div>
            {canDelete &&
              (confirming ? (
                <div className="flex items-center gap-2">
                  <span className="text-2xs text-muted">Delete this recording permanently?</span>
                  <button className="btn-danger" disabled={del.isPending} onClick={() => del.mutate()}>
                    {del.isPending ? "Deleting…" : "Yes, delete"}
                  </button>
                  <button className="btn-ghost" disabled={del.isPending} onClick={() => setConfirming(false)}>
                    Cancel
                  </button>
                </div>
              ) : (
                // Two steps on purpose. This is the only irreversible action in the
                // console: the evidence of what someone did on a privileged device
                // does not come back, and a single mis-aimed click should not be
                // able to destroy it.
                <button className="btn-ghost text-danger" onClick={() => setConfirming(true)}>
                  <IconTrash size={15} /> Delete recording
                </button>
              ))}
          </div>
          <div className="flex items-center gap-2">
            <ExportRecording
              session={session}
              deviceLabel={deviceLabel}
              userLabel={userLabel}
              available={available}
            />
            <button className="btn-ghost" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      }
    >
      {delError && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2">
          <IconAlert size={15} className="mt-0.5 shrink-0 text-danger" />
          <p className="text-xs text-fg">{delError}</p>
        </div>
      )}
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.9fr)_minmax(0,1fr)]">
        <div className="min-w-0">
          {recording.isLoading ? (
            <Skeleton className="h-72" />
          ) : notRecorded ? (
            <div className="flex h-72 flex-col items-center justify-center gap-2 rounded-xl border border-line bg-surface-2/40 px-6 text-center">
              <IconFilm size={22} className="text-faint" />
              <p className="text-sm text-muted">This session wasn't recorded.</p>
              <p className="max-w-sm text-2xs text-faint">
                Recording is set per device. Turn it on from the device's page, and future sessions to it will be
                captured.
              </p>
            </div>
          ) : available.length > 0 ? (
            <div className="space-y-3">
              {/* A terminal device can be set to capture a transcript AND video,
                  and they are different evidence: the transcript is exactly what
                  the device printed, the video is what the operator saw. Picking
                  one for the reviewer would hide the other, so both are offered
                  whenever both exist. One capture renders no tabs at all. */}
              {available.length > 1 && (
                <div className="flex gap-1 rounded-lg border border-line bg-surface-2/40 p-1">
                  {available.map((v) => (
                    <button
                      key={v}
                      className={cn(
                        "flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition",
                        view === v ? "bg-accent-soft text-accent" : "text-muted hover:text-fg",
                      )}
                      onClick={() => setView(v)}
                    >
                      {VIEW_LABEL[v]}
                    </button>
                  ))}
                </div>
              )}
              {view === "video" && <SessionPlayer sessionId={session.id} />}
              {view === "transcript" && <TranscriptPlayer sessionId={session.id} />}
              {view === "desktop" && <DesktopReplay sessionId={session.id} />}
            </div>
          ) : (
            <div className="flex h-72 flex-col items-center justify-center gap-2 rounded-xl border border-line bg-surface-2/40 px-6 text-center">
              <IconFilm size={22} className="text-faint" />
              <p className="text-sm text-muted">
                {session.status === "active"
                  ? "Still recording — the replay is written when the session ends."
                  : "Nothing was captured."}
              </p>
            </div>
          )}
        </div>

        <div className="min-w-0 space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge value={session.status} />
            <Badge tone="neutral">{session.protocol}</Badge>
            <HeldCell session={session} />
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
            <DField label="User" wide>{userLabel ?? <span className="font-mono text-xs">{session.user_id}</span>}</DField>
            <DField label="Device" wide>{deviceLabel ?? <span className="font-mono text-xs">{session.device_id}</span>}</DField>
            <DField label="Started">{absLocal(started)}</DField>
            <DField label="Ended">{session.ended_at ? absLocal(session.ended_at) : "—"}</DField>
            <DField label="Last activity">
              {session.last_activity_at ? absLocal(session.last_activity_at) : <span className="text-faint">none recorded</span>}
            </DField>
            <DField label="Authorized until">
              {session.granted_until ? absLocal(session.granted_until) : <span className="text-faint">no fixed window</span>}
            </DField>
            <DField label="Client IP"><span className="font-mono text-xs">{session.client_ip || "—"}</span></DField>
            <DField label="Gateway"><span className="font-mono text-xs">{session.gateway_node || "—"}</span></DField>
            {session.end_reason && <DField label="End reason" wide>{session.end_reason}</DField>}
            {session.user_agent && (
              <DField label="Client" wide>
                <span className="break-all font-mono text-2xs text-muted">{session.user_agent}</span>
              </DField>
            )}
          </dl>

          <div>
            <div className="mb-2 text-2xs font-semibold uppercase tracking-wider text-faint">Authorization</div>
            <Authorization session={session} />
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-2xs font-semibold uppercase tracking-wider text-faint">Activity timeline</span>
              {events.data && <span className="text-2xs text-faint">{events.data.length} events</span>}
            </div>
            {events.isLoading ? (
              <Skeleton className="h-32" />
            ) : !events.data || events.data.length === 0 ? (
              <EmptyState message="No page activity was recorded for this session." />
            ) : (
              <div className="max-h-64 overflow-auto pr-1">
                <ActivityTimeline events={events.data} />
              </div>
            )}
          </div>

          <p className="border-t border-line pt-3 text-2xs text-faint">
            Captured server-side. Times are shown in your local timezone.
          </p>
        </div>
      </div>
    </Modal>
  );
}

function ActivityTimeline({ events }: { events: SessionEvent[] }) {
  return (
    <ol className="relative space-y-1">
      <span className="absolute bottom-2 left-[6px] top-2 w-px bg-line" aria-hidden />
      {events.map((e, i) => {
        const path = typeof e.data?.path === "string" ? (e.data.path as string) : "";
        const method = typeof e.data?.method === "string" ? (e.data.method as string) : "";
        return (
          <li key={i} className="relative flex items-start gap-3 rounded-lg py-1.5 pl-5 pr-1 transition hover:bg-surface-2/50">
            <span className="absolute left-0 top-2.5 h-[11px] w-[11px] -translate-x-px rounded-full border-2 border-surface bg-accent/70" />
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-1.5">
                {method && <span className="font-mono text-2xs font-semibold text-accent">{method}</span>}
                <span className="truncate font-mono text-xs text-fg">{path || e.kind}</span>
              </div>
            </div>
            <time className="shrink-0 font-mono text-2xs tabular-nums text-faint">
              {plausibleDate(e.ts)?.toLocaleTimeString() ?? "—"}
            </time>
          </li>
        );
      })}
    </ol>
  );
}

/* ---- Exporting the evidence off the platform -------------------------------
   A recording is only useful as evidence if it can leave: attached to a ticket,
   handed to an auditor, kept past the retention window. Everything here is a
   read of artifacts the reviewer can already replay — the export adds no new
   access, it just writes them to a file. */

/** Strips ANSI/VT control sequences so an exported transcript is readable text.
 *
 *  The stored transcript is exactly what the device emitted, escape codes and
 *  all, because that is what makes it faithful and replayable. A .txt full of
 *  `ESC[1;32m` is faithful and unreadable, and the point of exporting is that
 *  somebody outside GuardRail can read it — so the export strips them and the
 *  original stays untouched in the blob store. */
function stripAnsi(s: string): string {
  return (
    s
      // OSC (window title and friends): ESC ] ... terminated by BEL or ST.
      // Removed first, because its payload can contain bytes the CSI pattern
      // below would otherwise chew into.
      .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, "")
      // CSI: ESC [ params intermediates final. Covers colour, cursor moves and
      // erase-line — the bulk of what a terminal session emits.
      .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
      // Remaining two-character escapes (ESC =, ESC >, charset selects).
      .replace(/\x1b[@-Z\\-_]/g, "")
      // A bare CR redraws the current line — progress bars, spinners. Kept as a
      // newline so the export shows the successive states rather than one line
      // overwritten into nonsense.
      .replace(/\r(?!\n)/g, "\n")
  );
}

/** A filename that identifies the session without needing the console open. */
function exportBase(session: Session, deviceLabel?: string): string {
  const name = (deviceLabel ?? session.device_name ?? "device").replace(/[^A-Za-z0-9._-]+/g, "-");
  return `guardrail-${name}-${session.id.slice(0, 8)}`;
}

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function ExportRecording({
  session,
  deviceLabel,
  userLabel,
  available,
}: {
  session: Session;
  deviceLabel?: string;
  userLabel?: string;
  available: ReplayView[];
}) {
  const [busy, setBusy] = useState<ReplayView | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (available.length === 0) return null;

  // The header names the device and the session id explicitly, so an exported
  // file still says what it is after the device has been deleted from GuardRail.
  // The stored session carries that identity; this just writes it down.
  const header = [
    "GuardRail session recording",
    `Session ID   : ${session.id}`,
    `Device       : ${deviceLabel ?? session.device_name ?? "(name not recorded)"}`,
    `Device ID    : ${session.device_id}`,
    `Device addr  : ${session.device_address ?? "-"}`,
    `Device type  : ${session.device_type ?? "-"}`,
    `Operator     : ${userLabel ?? session.user_email ?? session.user_id ?? "-"}`,
    `Protocol     : ${session.protocol}`,
    `Started (UTC): ${session.started_at ?? session.created_at ?? "-"}`,
    `Ended (UTC)  : ${session.ended_at ?? "(still active)"}`,
    `Client IP    : ${session.client_ip ?? "-"}`,
    "",
    "-".repeat(72),
    "",
  ].join("\n");

  const run = async (v: ReplayView) => {
    setBusy(v);
    setErr(null);
    try {
      const base = exportBase(session, deviceLabel);
      if (v === "transcript") {
        const { data } = await api.get(`/sessions/${session.id}/recording/transcript`, {
          responseType: "arraybuffer",
        });
        const text = new TextDecoder().decode(new Uint8Array(data as ArrayBuffer));
        download(new Blob([header + stripAnsi(text)], { type: "text/plain;charset=utf-8" }), `${base}-transcript.txt`);
      } else if (v === "desktop") {
        // A Guacamole protocol dump. Exported as-is: it is replayable by
        // guacamole tooling, and re-encoding it here would be inventing a format.
        const { data } = await api.get(`/sessions/${session.id}/recording/desktop`, { responseType: "arraybuffer" });
        download(new Blob([data as ArrayBuffer], { type: "application/octet-stream" }), `${base}-desktop.guac`);
      } else {
        // Frames plus the index that gives them their timing. Both are needed —
        // the frames alone are a concatenated blob with no boundaries — so they
        // are written as two files rather than one that cannot be replayed.
        const [frames, manifest] = await Promise.all([
          api.get(`/sessions/${session.id}/recording/frames`, { responseType: "arraybuffer" }),
          api.get(`/sessions/${session.id}/recording/manifest`, { responseType: "arraybuffer" }),
        ]);
        download(new Blob([frames.data as ArrayBuffer], { type: "application/octet-stream" }), `${base}-frames.bin`);
        download(new Blob([manifest.data as ArrayBuffer], { type: "application/json" }), `${base}-frames-manifest.json`);
      }
    } catch (e) {
      setErr(problemDetail(e, "The recording could not be exported."));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex items-center gap-2">
      {err && <span className="text-2xs text-danger">{err}</span>}
      {available.map((v) => (
        <button key={v} className="btn-ghost" disabled={busy !== null} onClick={() => void run(v)}>
          <IconDownload size={15} />
          {busy === v ? "Exporting…" : available.length > 1 ? `Export ${VIEW_LABEL[v].toLowerCase()}` : "Export recording"}
        </button>
      ))}
    </div>
  );
}

function DField({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={cn(wide && "col-span-2")}>
      <dt className="text-2xs font-semibold uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mt-0.5 text-sm text-fg">{children}</dd>
    </div>
  );
}

/* ---- How long access was actually held --------------------------------------
   Not `ended_at - started_at`. See sessionSpan in lib/dates: the reaper that
   closes a lapsed session only runs while the API does, so a record closed after
   an outage reports the outage as access. The span is measured to whichever came
   first — the record closing, or authorization running out — and any time the
   record stayed open past its window is called out rather than folded in.

   Calling it out rather than hiding it is the point: a session still sitting
   open after its grant expired is a finding, and quietly capping the number
   would bury exactly the thing worth seeing. */
export function HeldCell({ session }: { session: Session }) {
  const span = sessionSpan(session);
  if (!span) return <span className="text-xs text-faint">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="font-mono text-xs tabular-nums text-muted">{span.label}</span>
      {span.live && <span className="text-2xs text-success">live</span>}
      {span.overrun && (
        <span
          className="cursor-help rounded border border-warn/30 bg-warn/10 px-1 py-px text-[10px] font-medium leading-none text-warn"
          title={`The record stayed open ${span.overrun} after access expired. Nothing authorized that time — the session was closed late, which happens when the broker is not running to close it on time.`}
        >
          +{span.overrun} past window
        </span>
      )}
    </span>
  );
}

/* ---- How the session was authorized -----------------------------------------
   A session record that says only "started, ended, by whom" cannot answer the
   question a reviewer actually has: was this allowed, who allowed it, and when.
   On a gated device that answer exists — the approval request carries it — and
   it is linked to the session by session_id. */
function Authorization({ session }: { session: Session }) {
  const req = useQuery<AccessRequest[]>({
    queryKey: ["session-approval", session.id],
    // The approvals endpoint answers under `requests`, not `data` — the one
    // listing in the API that does.
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests", {
        params: { session_id: session.id, limit: 1 },
      })).data.requests ?? [],
  });

  if (req.isLoading) return <Skeleton className="h-16" />;
  const r = (req.data ?? [])[0];

  if (!r) {
    return (
      <p className="rounded-lg border border-line bg-surface-2/40 px-3 py-2 text-xs text-muted">
        No approval was needed — this device does not require one, or the person connecting was exempt.
      </p>
    );
  }

  const asked = plausibleDate(r.created_at);
  // The decision that settled it is the last one recorded — under a two-person
  // rule the earlier votes are steps toward it, not the moment access was given.
  const last = r.decisions?.[r.decisions.length - 1];
  const decided = plausibleDate(last?.decided_at);
  return (
    <div className="space-y-2 rounded-lg border border-line bg-surface-2/40 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge value={r.status} />
        {r.is_emergency && <Badge tone="danger">emergency — taken first, reviewed after</Badge>}
        {r.granted_minutes ? <Badge tone="neutral">{r.granted_minutes}m granted</Badge> : null}
      </div>
      <dl className="space-y-1.5 text-xs">
        <div className="flex gap-2">
          <dt className="w-20 shrink-0 text-faint">Reason</dt>
          <dd className="min-w-0 flex-1 text-fg">{r.reason || "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-20 shrink-0 text-faint">Asked</dt>
          <dd className="min-w-0 flex-1 text-fg">{asked ? asked.toLocaleString() : "—"}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-20 shrink-0 text-faint">Decided</dt>
          <dd className="min-w-0 flex-1 text-fg">
            {decided ? decided.toLocaleString() : "—"}
            {asked && decided && (
              <span className="ml-1.5 text-faint">· {Math.max(0, Math.round((decided.getTime() - asked.getTime()) / 60000))}m wait</span>
            )}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-20 shrink-0 text-faint">Approvers</dt>
          <dd className="min-w-0 flex-1 text-fg">
            {r.decisions && r.decisions.length > 0
              ? r.decisions.map((d) => `${d.by || "unknown"} · ${d.decision === "approve" ? "approved" : "denied"}`).join(", ")
              : `${r.approvals ?? 0} of ${r.min_approvals ?? 1} — nobody has decided yet`}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-20 shrink-0 text-faint">Window</dt>
          <dd className="min-w-0 flex-1 text-fg">
            {session.granted_until
              ? `until ${new Date(session.granted_until).toLocaleString()}`
              : "no fixed window"}
          </dd>
        </div>
      </dl>
    </div>
  );
}
