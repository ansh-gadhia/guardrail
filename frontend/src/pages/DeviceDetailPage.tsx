import { type ReactNode } from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import type { AssetGroup, Device, Session, UserRow } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, Panel, Badge, StatusBadge, EmptyState, ErrorNote, Skeleton, cn } from "@/components/ui";
import { DeviceStatusBadge } from "@/components/DeviceHealthDot";
import { GroupPicker } from "@/components/GroupPicker";
import { toast } from "@/components/Toast";
import { deviceTypeLabel, RecordingToggle, DeliveryModeField, isWebScheme } from "./DevicesPage";
import { IconDevices, IconSessions, IconAudit, IconClock, IconGlobe, IconChevronRight, IconFilm } from "@/components/icons";

interface DeviceAuditRow {
  ts: string;
  actor: string;
  action: string;
  result: string;
  ip?: string;
  detail?: Record<string, unknown> | null;
}

/* ---- time helpers (UTC in, local out) ---- */
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
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}
const startedOf = (s: Session) => s.started_at ?? s.created_at;

/* Group membership, edited in place. Membership is an access decision — a device
   moving into a group grants every role scoped to that group — so it saves on
   change and says so, rather than hiding behind a separate edit mode. */
function DeviceGroups({ device, canEdit }: { device: Device; canEdit: boolean }) {
  const qc = useQueryClient();
  const canReadGroups = useAuth((s) => s.has("group:read"));
  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data,
    enabled: canReadGroups,
  });

  const save = useMutation({
    mutationFn: async (ids: string[]) => api.patch(`/devices/${device.id}`, { ...toDeviceBody(device), group_ids: ids }),
    onSuccess: () => {
      toast.success("Groups updated");
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not update groups")),
  });

  const ids = device.group_ids ?? [];
  if (!canEdit) {
    const names = (groups.data ?? []).filter((g) => ids.includes(g.id));
    if (!names.length) return <span className="text-muted">—</span>;
    return (
      <span className="flex flex-wrap gap-1">
        {names.map((g) => (
          <Badge key={g.id} tone="neutral">{g.name}</Badge>
        ))}
      </span>
    );
  }
  return <GroupPicker value={ids} onChange={(next) => save.mutate(next)} />;
}

/* The recording policy, changeable only by the device's owner or a super admin.
   The server decides that (can_set_recording) and we honour its answer rather
   than re-deriving the rule here and risking a disagreement. */
function DeviceRecording({ device }: { device: Device }) {
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: async (on: boolean) =>
      api.patch(`/devices/${device.id}`, {
        ...toDeviceBody(device),
        record_sessions: on,
        // Recording a web device only exists under isolation, so switching it on
        // switches the delivery mode with it. Sent as one request because the
        // server judges the pair, not each field on its own — and rightly refuses
        // a recorded proxy device, which would capture nothing. An SSH session is
        // recorded by its own gateway as a transcript and needs no browser, so its
        // delivery mode is left alone.
        delivery_mode: on && isWebScheme(device.scheme) ? "isolated" : device.delivery_mode,
      }),
    onSuccess: (_d, on) => {
      toast.success(on ? "Sessions to this device will be recorded" : "Recording turned off for this device");
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not change the recording setting")),
  });

  return (
    <RecordingToggle
      checked={device.record_sessions}
      disabled={!device.can_set_recording || save.isPending}
      onChange={(v) => save.mutate(v)}
      hint={
        device.can_set_recording
          ? undefined
          : "Only the person who added this device, or a super admin, can change this."
      }
    />
  );
}

/* How sessions reach this device, editable in place.

   Gated on can_set_recording whenever recording is on, because switching to the
   proxy necessarily turns recording off — the proxy never sees pixels. That is a
   recording-policy change wearing a delivery-setting hat, and it answers to the
   same rule: only the device's owner or a super admin. Without this the control
   would look editable and the server would refuse the save. */
function DeviceDelivery({ device, canEdit }: { device: Device; canEdit: boolean }) {
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: async (mode: string) =>
      api.patch(`/devices/${device.id}`, {
        ...toDeviceBody(device),
        delivery_mode: mode,
        record_sessions: mode === "proxy" ? false : device.record_sessions,
      }),
    onSuccess: (_d, mode) => {
      toast.success(
        mode === "isolated"
          ? "Sessions to this device now open in an isolated browser"
          : "Sessions to this device are now reverse-proxied",
      );
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not change how sessions reach this device")),
  });

  // A terminal or desktop device has one gateway and nothing to choose between,
  // and the server refuses an isolated one. Offering the control would be
  // offering a setting that cannot be saved.
  if (!isWebScheme(device.scheme)) return null;

  const locked = device.record_sessions && !device.can_set_recording;
  return (
    <DeliveryModeField
      value={device.delivery_mode}
      disabled={!canEdit || locked || save.isPending}
      onChange={(v) => save.mutate(v)}
      hint={
        locked
          ? "This device is recorded, and switching to the reverse proxy would end that. Only the person who added it, or a super admin, can change it."
          : undefined
      }
    />
  );
}

/* The device's idle timeout, editable in place. Saved on blur rather than on
   every keystroke: typing "90" passes through "9", and saving that would set a
   nine-minute timeout on a live device for as long as it took to type the
   second digit. */
function DeviceIdleTimeout({ device, canEdit }: { device: Device; canEdit: boolean }) {
  const qc = useQueryClient();
  const [value, setValue] = useState(String(device.idle_timeout_minutes ?? 60));

  const save = useMutation({
    mutationFn: async (mins: number) =>
      api.patch(`/devices/${device.id}`, { ...toDeviceBody(device), idle_timeout_minutes: mins }),
    onSuccess: (_d, mins) => {
      toast.success(mins === 0 ? "Sessions will not be ended for being idle" : `Sessions end after ${mins} idle minutes`);
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => {
      toast.error(problemDetail(err, "Could not change the idle timeout"));
      setValue(String(device.idle_timeout_minutes ?? 60));
    },
  });

  if (!canEdit) {
    const m = device.idle_timeout_minutes ?? 0;
    return <span>{m === 0 ? "Never" : `${m} min`}</span>;
  }
  const commit = () => {
    const mins = Number(value);
    if (value.trim() === "" || Number.isNaN(mins) || mins < 0 || mins > 1440) {
      setValue(String(device.idle_timeout_minutes ?? 60));
      return;
    }
    if (mins !== device.idle_timeout_minutes) save.mutate(mins);
  };
  return (
    <span className="inline-flex items-center gap-1.5">
      <input
        className="input w-20 py-1 text-center"
        inputMode="numeric"
        aria-label="Idle timeout in minutes"
        value={value}
        disabled={save.isPending}
        onChange={(e) => setValue(e.target.value.replace(/\D/g, "").slice(0, 4))}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") e.currentTarget.blur();
        }}
      />
      <span className="text-xs text-muted">min {Number(value) === 0 ? "(never)" : ""}</span>
    </span>
  );
}

// PATCH /devices/:id replaces the whole device, so a group-only change still has
// to send the rest of the device back unchanged.
function toDeviceBody(d: Device) {
  return {
    name: d.name,
    description: d.description,
    host: d.host,
    port: d.port,
    scheme: d.scheme,
    vendor: d.vendor,
    device_type: d.device_type,
    verify_tls: d.verify_tls,
    tags: d.tags,
    allow_unmanaged: d.allow_unmanaged,
  };
}

export function DeviceDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const has = useAuth((s) => s.has);

  const device = useQuery<Device>({
    queryKey: ["device", id],
    queryFn: async () => (await api.get<Device>(`/devices/${id}`)).data,
    enabled: !!id,
  });
  const sessions = useQuery<Session[]>({
    queryKey: ["sessions", "device", id],
    queryFn: async () => (await api.get<{ data: Session[] }>("/sessions", { params: { device_id: id, limit: 100 } })).data.data,
    enabled: !!id && has("session:read"),
  });
  const audit = useQuery<DeviceAuditRow[]>({
    queryKey: ["audit", "device", id],
    queryFn: async () =>
      (await api.get<{ data: DeviceAuditRow[] }>("/audit", { params: { target_type: "device", target_id: id, limit: 100 } })).data.data,
    enabled: !!id && has("log:read"),
  });
  const users = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data,
    enabled: has("user:read"),
  });
  const userEmail = useMemo(() => {
    const m = new Map<string, string>();
    (users.data ?? []).forEach((u) => m.set(u.user_id, u.email));
    return m;
  }, [users.data]);

  const d = device.data;

  return (
    <div className="space-y-5">
      <nav className="flex items-center gap-1.5 text-sm text-muted">
        <button className="transition hover:text-fg" onClick={() => navigate("/devices")}>
          Devices
        </button>
        <IconChevronRight size={14} className="text-faint" />
        <span className="truncate font-medium text-fg">{d?.name ?? id.slice(0, 8)}</span>
      </nav>

      {device.isLoading ? (
        <Skeleton className="h-40" />
      ) : device.isError || !d ? (
        <ErrorNote message="Couldn't load this device." />
      ) : (
        <>
          <PageHero
            icon={IconDevices}
            eyebrow={deviceTypeLabel(d.device_type)}
            title={d.name}
            subtitle={d.description || d.url}
            actions={
              <DeviceStatusBadge device={d} />
            }
          />

          <Panel title="Details" icon={IconDevices}>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
              <DField label="Endpoint" wide>
                <span className="font-mono text-xs">{d.url}</span>
              </DField>
              <DField label="Type">{deviceTypeLabel(d.device_type)}</DField>
              <DField label="Vendor">{d.vendor || "—"}</DField>
              <DField label="Host">
                <span className="font-mono text-xs">{d.host}</span>
              </DField>
              <DField label="Added">{absLocal(d.created_at)}</DField>
              <DField label="TLS verify">{d.verify_tls ? "On" : "Off (self-signed OK)"}</DField>
              <DField label="End when idle">
                <DeviceIdleTimeout device={d} canEdit={has("device:write")} />
              </DField>
              <DField label="Credential">
                {d.has_credential ? (
                  <Badge tone="success" dot>bound</Badge>
                ) : d.allow_unmanaged ? (
                  <Badge tone="warn" dot>break-glass</Badge>
                ) : (
                  <Badge tone="danger" dot>none</Badge>
                )}
              </DField>
              {d.tags && d.tags.length > 0 && (
                <DField label="Tags" wide>
                  <span className="flex flex-wrap gap-1">
                    {d.tags.map((t) => (
                      <Badge key={t} tone="neutral">{t}</Badge>
                    ))}
                  </span>
                </DField>
              )}
              <DField label="Asset groups" wide>
                <DeviceGroups device={d} canEdit={has("device:write")} />
              </DField>
            </dl>
          </Panel>

          <Panel
            title="Session delivery"
            icon={IconFilm}
            subtitle="How sessions reach this device, and whether they are screen-recorded"
          >
            <DeviceDelivery device={d} canEdit={has("device:write")} />
            <DeviceRecording device={d} />
          </Panel>

          <Panel title="Access history" icon={IconSessions} subtitle="Every brokered session to this device" bodyClassName="p-0">
            {!has("session:read") ? (
              <div className="p-4"><EmptyState message="You don't have permission to view sessions." /></div>
            ) : sessions.isLoading ? (
              <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
            ) : (sessions.data ?? []).length === 0 ? (
              <EmptyState icon={IconSessions} message="No sessions have been brokered to this device yet." />
            ) : (
              <div className="divide-y divide-line">
                {(sessions.data ?? []).map((s) => (
                  <div key={s.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-sm">
                    <span className="min-w-0 flex-1 truncate text-fg">{userEmail.get(s.user_id ?? "") ?? (s.user_id ?? "").slice(0, 8)}</span>
                    <StatusBadge value={s.status} />
                    <span className="whitespace-nowrap text-xs text-muted">{absLocal(startedOf(s))}</span>
                    <span className="w-16 text-right font-mono text-xs tabular-nums text-muted">{duration(startedOf(s), s.ended_at)}</span>
                    <span className="inline-flex w-28 items-center justify-end gap-1 font-mono text-2xs text-faint">
                      <IconGlobe size={12} />{s.client_ip || "—"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel title="Audit trail" icon={IconAudit} subtitle="Configuration & access events for this device" bodyClassName="p-0">
            {!has("log:read") ? (
              <div className="p-4"><EmptyState message="You don't have permission to view the audit log." /></div>
            ) : audit.isLoading ? (
              <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
            ) : (audit.data ?? []).length === 0 ? (
              <EmptyState icon={IconAudit} message="No audit events recorded for this device." />
            ) : (
              <ol className="divide-y divide-line">
                {(audit.data ?? []).map((a, i) => {
                  const ok = (a.result || "").toLowerCase() === "success";
                  return (
                    <li key={i} className="flex items-center gap-3 px-4 py-2.5">
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", ok ? "bg-success" : "bg-danger")} />
                      <span className="w-40 shrink-0 truncate font-mono text-xs text-accent">{a.action}</span>
                      <span className="min-w-0 flex-1 truncate text-sm text-muted">{a.actor || "system"}</span>
                      <span className="inline-flex items-center gap-1 whitespace-nowrap text-2xs text-faint">
                        <IconClock size={12} />{relTime(a.ts)}
                      </span>
                    </li>
                  );
                })}
              </ol>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}

function DField({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={cn(wide && "col-span-2 sm:col-span-1")}>
      <dt className="text-2xs font-semibold uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mt-0.5 text-sm text-fg">{children}</dd>
    </div>
  );
}
