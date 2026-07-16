import { useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Session, SessionEvent, Device, UserRow, RecordingMeta } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, StatCluster, Panel, Badge, StatusBadge, Modal, EmptyState, ErrorNote, Skeleton, cn } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { IconFilm, IconDevices, IconTrash, IconAlert } from "@/components/icons";
import { SessionPlayer } from "@/components/SessionPlayer";
import { TranscriptPlayer } from "@/components/TranscriptPlayer";
import { DesktopReplay } from "@/components/DesktopReplay";

/* ---- time + duration helpers (UTC in, local out; math on epoch millis) ---- */
function absLocal(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function relTime(iso?: string): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "";
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

export function RecordingsPage() {
  const has = useAuth((s) => s.has);
  const [selected, setSelected] = useState<Session | null>(null);

  const sessions = useQuery<Session[]>({
    queryKey: ["sessions", "all"],
    queryFn: async () => (await api.get<{ data: Session[] }>("/sessions", { params: { limit: 200 } })).data.data,
    refetchInterval: 10_000,
  });
  const devices = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: async () => (await api.get<{ data: Device[] }>("/devices")).data.data,
  });
  const users = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data,
    enabled: has("user:read"),
  });

  const deviceName = useMemo(() => {
    const m = new Map<string, string>();
    (devices.data ?? []).forEach((d) => m.set(d.id, d.name));
    return m;
  }, [devices.data]);
  const userEmail = useMemo(() => {
    const m = new Map<string, string>();
    (users.data ?? []).forEach((u) => m.set(u.user_id, u.email));
    return m;
  }, [users.data]);

  const rows = sessions.data ?? [];
  const stats = useMemo(() => {
    const active = rows.filter((r) => r.status === "active").length;
    const devs = new Set(rows.map((r) => r.device_id)).size;
    return { total: rows.length, active, ended: rows.filter((r) => r.status === "ended" || r.status === "expired").length, devs };
  }, [rows]);

  const columns: Column<Session>[] = [
    {
      key: "user",
      header: "User",
      value: (s) => userEmail.get(s.user_id ?? "") ?? s.user_id ?? "",
      cell: (s) => {
        const email = userEmail.get(s.user_id ?? "");
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
      value: (s) => deviceName.get(s.device_id) ?? s.device_id,
      cell: (s) => (
        <span className="inline-flex items-center gap-1.5 text-sm text-fg">
          <IconDevices size={14} className="text-faint" />
          {deviceName.get(s.device_id) ?? <span className="font-mono text-xs text-faint">{s.device_id.slice(0, 8)}</span>}
        </span>
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
          rows.length > 0 ? (
            <StatCluster
              items={[
                { label: "Sessions", value: stats.total },
                { label: "Active now", value: stats.active, tone: stats.active > 0 ? "accent" : undefined },
                { label: "Ended", value: stats.ended },
                { label: "Devices", value: stats.devs },
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
        ) : rows.length === 0 ? (
          <EmptyState icon={IconFilm} title="No sessions yet" message="Brokered device sessions and their activity will be recorded here." />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(s) => s.id}
            searchPlaceholder="Search by user, device, IP…"
            pageSize={12}
            exportName="session-recordings"
            onRowClick={setSelected}
          />
        )}
      </Panel>

      {selected && (
        <RecordingPopup
          session={selected}
          deviceLabel={deviceName.get(selected.device_id)}
          userLabel={userEmail.get(selected.user_id ?? "")}
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
          <button className="btn-ghost" onClick={onClose}>
            Close
          </button>
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
          ) : hasVideo ? (
            <SessionPlayer sessionId={session.id} />
          ) : hasTranscript ? (
            // A terminal session was captured as text, not pixels. Same modal,
            // different reader — which is what the recording itself reports.
            <TranscriptPlayer sessionId={session.id} />
          ) : hasDesktop ? (
            // A desktop was captured as a Guacamole dump: neither frames nor
            // text, and a third reader. Without this branch it fell through to
            // "Nothing was captured" while its bytes sat in the blob store.
            <DesktopReplay sessionId={session.id} />
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
              {new Date(e.ts).toLocaleTimeString()}
            </time>
          </li>
        );
      })}
    </ol>
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
