import { type ReactNode } from "react";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import { absLocal, plausibleDate, relTime, startedOf } from "@/lib/dates";
import type { AssetGroup, Device, Session, UserRow, RecordingKind } from "@/lib/types";
import { RECORDING_KIND_INFO } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, Panel, Badge, StatusBadge, EmptyState, ErrorNote, Field, Modal, Skeleton, cn } from "@/components/ui";
import { DeviceStatusBadge } from "@/components/DeviceHealthDot";
import { GroupPicker } from "@/components/GroupPicker";
import { toast } from "@/components/Toast";
import { DeviceAccessPolicy } from "@/components/DeviceAccessPolicy";
import { SessionDetail, HeldCell } from "@/components/SessionDetail";
import {
  deviceTypeLabel, RecordingToggle, DeliveryModeField, isWebScheme,
  PROTOCOLS, DEVICE_TYPES, defaultPortFor,
} from "./DevicesPage";
import { IconDevices, IconSessions, IconAudit, IconClock, IconGlobe, IconChevronRight, IconFilm, IconKey } from "@/components/icons";

/** Outcome dot for the device's audit trail, matching the Audit Log's tones. */
const AUDIT_DOT: Record<string, string> = {
  success: "bg-success",
  pending: "bg-warn",
  denied: "bg-danger",
  failure: "bg-danger",
};

interface DeviceAuditRow {
  ts: string;
  actor: string;
  action: string;
  result: string;
  ip?: string;
  detail?: Record<string, unknown> | null;
}

/* ---- time helpers (UTC in, local out; zero/invalid dates guarded via plausibleDate) ---- */

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

  // Separate mutation from the master switch: this one changes what is captured,
  // not whether. Sent on its own so a failure to change the captures cannot leave
  // recording itself in a state nobody asked for.
  const saveKinds = useMutation({
    mutationFn: async (kinds: RecordingKind[]) =>
      api.patch(`/devices/${device.id}`, { ...toDeviceBody(device), recording_kinds: kinds }),
    onSuccess: (_d, kinds) => {
      toast.success(`Now capturing ${kinds.map((k) => RECORDING_KIND_INFO[k].label.toLowerCase()).join(" and ")}`);
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not change what is captured")),
  });

  return (
    <RecordingToggle
      checked={device.record_sessions}
      disabled={!device.can_set_recording || save.isPending || saveKinds.isPending}
      onChange={(v) => save.mutate(v)}
      scheme={device.scheme}
      kinds={device.recording_kinds}
      supportedKinds={device.supported_recording_kinds}
      onKindsChange={(next) => saveKinds.mutate(next)}
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


// ---- editing the device itself --------------------------------------------

// EditDeviceModal changes what the device IS: where it lives and what it is.
//
// The console could register a device and never change it again. Everything on
// this page was editable except the fields that actually identify the target —
// so a box that moved to a new address, or was typed in wrong, had to be deleted
// and re-registered, taking its sessions, recordings and audit trail with it.
// The API has always accepted the change; only the form was missing.
//
// Recording policy is deliberately NOT here. It is owner-or-super-admin, decided
// by the server, and lives in its own control above with that rule spelled out.
function EditDeviceModal({ device, onClose }: { device: Device; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    name: device.name,
    host: device.host,
    port: String(device.port || ""),
    scheme: device.scheme,
    vendor: device.vendor,
    device_type: device.device_type,
    description: device.description,
    verify_tls: device.verify_tls,
  });
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((s) => ({ ...s, [k]: v }));

  const save = useMutation({
    mutationFn: async () =>
      api.patch(`/devices/${device.id}`, {
        ...toDeviceBody(device),
        name: f.name.trim(),
        host: f.host.trim(),
        port: Number(f.port) || 0,
        scheme: f.scheme,
        vendor: f.vendor.trim(),
        device_type: f.device_type.trim(),
        description: f.description,
        verify_tls: f.verify_tls,
      }),
    onSuccess: () => {
      toast.success("Device updated");
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
      onClose();
    },
    onError: (e) => toast.error(problemDetail(e, "Could not update the device")),
  });

  const schemeChanged = f.scheme !== device.scheme;
  const known = DEVICE_TYPES.includes(f.device_type);

  return (
    <Modal
      title={`Edit ${device.name}`}
      icon={IconDevices}
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={save.isPending || !f.name.trim() || !f.host.trim()}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Save changes"}
          </button>
        </>
      }
    >
      {save.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(save.error, "Could not update the device")} />
        </div>
      )}
      <Field label="Name">
        <input className="input" value={f.name} onChange={(e) => set("name", e.target.value)} autoFocus />
      </Field>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <Field label="Host / IP" hint="Do not include the port here.">
            <input className="input" value={f.host} onChange={(e) => set("host", e.target.value)} />
          </Field>
        </div>
        <Field label="Port">
          <input
            className="input"
            inputMode="numeric"
            value={f.port}
            onChange={(e) => set("port", e.target.value.replace(/\D/g, "").slice(0, 5))}
            placeholder={defaultPortFor(f.scheme) || "443"}
          />
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Protocol" hint={PROTOCOLS.find((p) => p.value === f.scheme)?.hint}>
          <select
            className="input"
            value={f.scheme}
            onChange={(e) => {
              // The stored port belonged to the old protocol. Keeping 443 on a
              // device just switched to SSH produces a connection that times out
              // for no visible reason; the field stays editable for odd cases.
              const next = e.target.value;
              setF((s) => ({ ...s, scheme: next, port: defaultPortFor(next) }));
            }}
          >
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Device type">
          <div className="space-y-2">
            <select
              className="input"
              value={known ? f.device_type : "other"}
              onChange={(e) => set("device_type", e.target.value === "other" ? "" : e.target.value)}
            >
              {DEVICE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {deviceTypeLabel(t)}
                </option>
              ))}
              <option value="other">Other…</option>
            </select>
            {!known && (
              <input
                className="input"
                value={f.device_type}
                onChange={(e) => set("device_type", e.target.value)}
                placeholder="Custom device type"
              />
            )}
          </div>
        </Field>
      </div>
      <Field label="Vendor">
        <input className="input" value={f.vendor} onChange={(e) => set("vendor", e.target.value)} />
      </Field>
      <Field label="Description">
        <input className="input" value={f.description} onChange={(e) => set("description", e.target.value)} />
      </Field>
      {isWebScheme(f.scheme) && (
        <Field label="TLS" hint="Off accepts a self-signed or otherwise unverifiable certificate.">
          <label className="flex items-center gap-2 text-sm text-fg">
            <input
              type="checkbox"
              checked={f.verify_tls}
              onChange={(e) => set("verify_tls", e.target.checked)}
            />
            Verify the device's certificate
          </label>
        </Field>
      )}
      {/* Changing the protocol can invalidate things settled against the old one
          — a credential's injection method, the delivery mode, what a recording
          captures. The server refuses the combinations it cannot honour, so this
          is a warning rather than a block, but being refused after pressing Save
          is a worse way to learn it. */}
      {schemeChanged && (
        <p className="mt-1 text-xs text-warn">
          Changing the protocol from {device.scheme} to {f.scheme}
          {device.has_credential ? " may invalidate this device's credential — check how it authenticates after saving." : "."}
          {device.delivery_mode === "isolated" && !isWebScheme(f.scheme)
            ? " Isolated delivery is web-only, so this device will move back to the proxy."
            : ""}
        </p>
      )}
    </Modal>
  );
}

export function DeviceDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const has = useAuth((s) => s.has);
  const [editing, setEditing] = useState(false);
  // A session opened from the Access history below. The same panel the
  // Recordings page opens, shown here so a device's history is a way IN to
  // its sessions rather than a list you then have to go and find elsewhere.
  const [openSession, setOpenSession] = useState<Session | null>(null);

  const device = useQuery<Device>({
    queryKey: ["device", id],
    queryFn: async () => (await api.get<Device>(`/devices/${id}`)).data,
    enabled: !!id,
    // Health is repolled server-side on GUARDRAIL_HEALTH_POLL_INTERVAL (60s by
    // default); without a refetch the page kept showing whatever the device's
    // reachability was when it was opened, so a box that went down while someone
    // was looking at it stayed green until they reloaded.
    refetchInterval: 30_000,
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

          <Panel
            title="Details"
            icon={IconDevices}
            actions={
              has("device:write") ? (
                <button className="btn-subtle" onClick={() => setEditing(true)}>
                  Edit
                </button>
              ) : undefined
            }
          >
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

          <Panel
            title="Access policy"
            icon={IconKey}
            subtitle="Which account this device authenticates as, and who has to say yes before you reach it"
          >
            <DeviceAccessPolicy device={d} canEdit={has("device:write")} toBody={toDeviceBody} />
          </Panel>

          <Panel
            title="Access history"
            icon={IconSessions}
            subtitle="Every brokered session to this device — open one for its replay, activity and approval"
            bodyClassName="p-0"
          >
            {!has("session:read") ? (
              <div className="p-4"><EmptyState message="You don't have permission to view sessions." /></div>
            ) : sessions.isLoading ? (
              <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
            ) : (sessions.data ?? []).length === 0 ? (
              <EmptyState icon={IconSessions} message="No sessions have been brokered to this device yet." />
            ) : (
              <div className="divide-y divide-line">
                {(sessions.data ?? []).map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => setOpenSession(s)}
                    className="group flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-left text-sm transition hover:bg-surface-2/60"
                    title="Open this session — replay, activity, and how it was authorized"
                  >
                    <span className="min-w-0 flex-1 truncate text-fg">{userEmail.get(s.user_id ?? "") ?? (s.user_id ?? "").slice(0, 8)}</span>
                    <StatusBadge value={s.status} />
                    <span className="whitespace-nowrap text-xs text-muted">{absLocal(startedOf(s))}</span>
                    <span className="w-auto text-right"><HeldCell session={s} /></span>
                    <span className="inline-flex w-28 items-center justify-end gap-1 font-mono text-2xs text-faint">
                      <IconGlobe size={12} />{s.client_ip || "—"}
                    </span>
                    <IconChevronRight size={14} className="shrink-0 text-faint opacity-0 transition-opacity group-hover:opacity-100" />
                  </button>
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
                {(audit.data ?? []).map((a, i) => (
                  <li key={i} className="flex items-center gap-3 px-4 py-2.5">
                    {/* Anything-but-success was red, so a request merely waiting on an
                        approver looked like a refusal — the same lie the Audit Log's
                        badge used to tell. Pending is amber, and an outcome this
                        panel does not know is grey rather than an accusation. */}
                    <span className={cn("h-2 w-2 shrink-0 rounded-full", AUDIT_DOT[(a.result || "").toLowerCase()] ?? "bg-line-strong")} />
                    <span className="w-40 shrink-0 truncate font-mono text-xs text-accent">{a.action}</span>
                    <span className="min-w-0 flex-1 truncate text-sm text-muted">{a.actor || "system"}</span>
                    <span className="inline-flex items-center gap-1 whitespace-nowrap text-2xs text-faint">
                      <IconClock size={12} />{relTime(a.ts)}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        </>
      )}

      {editing && d && <EditDeviceModal device={d} onClose={() => setEditing(false)} />}
      {openSession && (
        <SessionDetail
          session={openSession}
          deviceLabel={openSession.device_name || d?.name}
          userLabel={userEmail.get(openSession.user_id ?? "")}
          onClose={() => setOpenSession(null)}
        />
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
