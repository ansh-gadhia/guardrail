import { useEffect, useMemo, useState, type ReactNode } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import { plausibleDate } from "@/lib/dates";
import type { Session, SessionEvent, RecordingMeta, Paged, SessionStats } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, StatCluster, Panel, Badge, StatusBadge, Modal, EmptyState, ErrorNote, Skeleton, cn } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { IconFilm, IconDevices, IconTrash, IconAlert, IconDownload } from "@/components/icons";
import { SessionPlayer } from "@/components/SessionPlayer";
import { TranscriptPlayer } from "@/components/TranscriptPlayer";
import { DesktopReplay } from "@/components/DesktopReplay";

/* ---- time + duration helpers (UTC in, local out; math on epoch millis) ---- */
function absLocal(iso?: string): string {
  const d = plausibleDate(iso);
  return d ? d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
}
function relTime(iso?: string): string {
  const d = plausibleDate(iso);
  if (!d) return "";
  const t = d.getTime();
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
function duration(start?: string, end?: string): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const ms = e - s;
  if (Number.isNaN(ms) || ms < 0) return "—";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${sec % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}
const startedOf = (s: Session) => s.started_at ?? s.created_at;

/** The replays a recording can offer. One recording may hold more than one. */
type ReplayView = "transcript" | "video" | "desktop";
const VIEW_LABEL: Record<ReplayView, string> = {
  transcript: "Transcript",
  video: "Video",
  desktop: "Desktop replay",
};

/** Column keys the server can sort on (see access.SessionSortColumns). */
const SERVER_SORTABLE = new Set(["user", "device", "protocol", "status", "started", "duration", "ip"]);

/** Debounces a value so typing in the search box does not fire a query per keystroke. */
function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function RecordingsPage() {
  const [selected, setSelected] = useState<Session | null>(null);

  // Paging, search and sort live here and travel to the server. The table is
  // handed exactly one page and told the real total.
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(12);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const search = useDebounced(query.trim(), 300);

  // Any change to what is being asked for restarts at page one — otherwise a
  // search that narrows to three rows leaves you on page nine looking at
  // nothing, which reads as "no results".
  useEffect(() => setPage(0), [search, sortKey, sortDir]);

  const listParams = useMemo(
    () => ({
      limit: pageSize,
      offset: page * pageSize,
      ...(search ? { q: search } : {}),
      ...(sortKey && SERVER_SORTABLE.has(sortKey) ? { sort: sortKey, dir: sortDir } : {}),
    }),
    [pageSize, page, search, sortKey, sortDir],
  );

  const sessions = useQuery<Paged<Session>>({
    queryKey: ["sessions", "page", listParams],
    queryFn: async () => (await api.get<Paged<Session>>("/sessions", { params: listParams })).data,
    refetchInterval: 10_000,
    // Keeps the previous page on screen while the next one loads, so paging does
    // not flash the empty state between requests.
    placeholderData: keepPreviousData,
  });

  // Counters come from their own endpoint and describe every session in the
  // tenant. They used to be computed from the fetched array, which meant they
  // silently stopped counting past the fetch limit.
  const stats = useQuery<SessionStats>({
    queryKey: ["session-stats"],
    queryFn: async () => (await api.get<SessionStats>("/sessions/stats")).data,
    refetchInterval: 10_000,
  });

  const rows = sessions.data?.data ?? [];
  const total = sessions.data?.total ?? 0;

  // Labels now ride along with each row, so this page no longer fetches every
  // user and every device just to name a dozen sessions.
  const deviceName = (s: Session) => s.device_name;
  const userEmail = (s: Session) => s.user_email;

  const columns: Column<Session>[] = [
    {
      key: "user",
      header: "User",
      value: (s) => userEmail(s) ?? s.user_id ?? "",
      cell: (s) => {
        const email = userEmail(s);
        return (
          <div className="flex items-center gap-2">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full accent-grad text-2xs font-semibold text-white ring-1 ring-white/20">
              {(email ?? "··").slice(0, 2).toUpperCase()}
            </span>
            <span className="truncate text-sm text-fg">{email ?? <span className="font-mono text-xs text-faint">{(s.user_id ?? "").slice(0, 8)}</span>}</span>
          </div>
        );
      },
    },
    {
      key: "device",
      header: "Device",
      value: (s) => deviceName(s) ?? s.device_address ?? s.device_id,
      // The name is the one recorded at connect, so a session still names its
      // device after that device has been deleted. The address underneath answers
      // "which box was that" when the name has been reused or means nothing now.
      cell: (s) => (
        <div className="leading-tight">
          <span className="inline-flex items-center gap-1.5 text-sm text-fg">
            <IconDevices size={14} className="text-faint" />
            {deviceName(s) ?? <span className="font-mono text-xs text-faint">{s.device_id.slice(0, 8)}</span>}
          </span>
          {s.device_address && <div className="pl-[22px] font-mono text-2xs text-faint">{s.device_address}</div>}
        </div>
      ),
    },
    {
      key: "protocol",
      header: "Protocol",
      value: (s) => s.protocol,
      cell: (s) => <Badge tone="neutral">{s.protocol}</Badge>,
    },
    {
      key: "status",
      header: "Status",
      value: (s) => s.status,
      cell: (s) => <StatusBadge value={s.status} />,
    },
    {
      key: "started",
      header: "Started",
      value: (s) => startedOf(s) ?? "",
      cell: (s) => (
        <div className="leading-tight">
          <div className="whitespace-nowrap text-sm text-fg">{absLocal(startedOf(s))}</div>
          <div className="text-2xs text-faint">{relTime(startedOf(s))}</div>
        </div>
      ),
    },
    {
      key: "duration",
      header: "Duration",
      value: (s) => {
        const st = startedOf(s);
        return st ? new Date(s.ended_at ?? Date.now()).getTime() - new Date(st).getTime() : 0;
      },
      cell: (s) => <span className="font-mono text-xs tabular-nums text-muted">{duration(startedOf(s), s.ended_at)}</span>,
    },
    {
      key: "ip",
      header: "Client IP",
      value: (s) => s.client_ip ?? "",
      cell: (s) => <span className="font-mono text-xs text-faint">{s.client_ip || "—"}</span>,
      align: "right",
    },
  ];

  return (
    <div className="space-y-5">
      <PageHero
        icon={IconFilm}
        eyebrow="Access"
        title="Recordings"
        subtitle="Every brokered session — who reached which device, when, for how long, and what they did."
        stats={
          stats.data ? (
            <StatCluster
              items={[
                { label: "Sessions", value: stats.data.total },
                { label: "Active now", value: stats.data.active, tone: stats.data.active > 0 ? "accent" : undefined },
                { label: "Ended", value: stats.data.ended },
                { label: "Devices", value: stats.data.devices },
              ]}
            />
          ) : undefined
        }
      />

      <Panel title="Session recordings" icon={IconFilm} bodyClassName="p-0">
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : sessions.isError ? (
          <div className="p-4">
            <ErrorNote message="Couldn't load session recordings. Try reloading." />
          </div>
        ) : total === 0 && !search ? (
          <EmptyState icon={IconFilm} title="No sessions yet" message="Brokered device sessions and their activity will be recorded here." />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(s) => s.id}
            searchPlaceholder="Search by user, device, IP, protocol…"
            exportName="session-recordings"
            emptyMessage={search ? `No sessions match “${search}”.` : "No results."}
            onRowClick={setSelected}
            server={{
              total,
              page,
              onPageChange: setPage,
              pageSize,
              onPageSizeChange: setPageSize,
              query,
              onQueryChange: setQuery,
              sortKey,
              sortDir,
              onSortChange: (k, d) => {
                setSortKey(k);
                setSortDir(d);
              },
              loading: sessions.isFetching,
              // Export pulls the whole filtered set rather than the page on
              // screen. Capped so a tenant with a very long history cannot turn
              // one click into an unbounded response.
              fetchAll: async () => {
                const { data } = await api.get<Paged<Session>>("/sessions", {
                  params: { ...listParams, limit: 5000, offset: 0 },
                });
                return data.data;
              },
            }}
          />
        )}
      </Panel>

      {selected && (
        <RecordingPopup
          session={selected}
          deviceLabel={deviceName(selected)}
          userLabel={userEmail(selected)}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

/* ---- Recording popup -------------------------------------------------------
   Opening a recording shows the whole session in one window: the replay on the
   left, and everything we know about the session on the right — who, what,
   from where, and the activity timeline. They belong together: the video shows
   what happened, and the metadata says who it was and whether they were
   supposed to be there. */
function RecordingPopup({
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
            <span className="text-xs text-muted">{duration(started, session.ended_at)}</span>
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
            <DField label="User" wide>{userLabel ?? <span className="font-mono text-xs">{session.user_id}</span>}</DField>
            <DField label="Device" wide>{deviceLabel ?? <span className="font-mono text-xs">{session.device_id}</span>}</DField>
            <DField label="Started">{absLocal(started)}</DField>
            <DField label="Ended">{session.ended_at ? absLocal(session.ended_at) : "—"}</DField>
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
