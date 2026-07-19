import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import { plausibleDate } from "@/lib/dates";
import type { Device, DeviceCredential, ConnectResult } from "@/lib/types";
import { injectionMethodsFor, defaultInjectionFor } from "@/lib/types";
import { useAuth } from "@/store/auth";
import {
  PageHero,
  Spinner,
  ErrorNote,
  EmptyState,
  Badge,
  Modal,
  Field,
  StatCluster,
  Skeleton,
  Switch,
  cn,
} from "@/components/ui";
import { DeviceStatusBadge } from "@/components/DeviceHealthDot";
import { GroupPicker } from "@/components/GroupPicker";
import {
  IconDevices,
  IconPlus,
  IconPlug,
  IconKey,
  IconTrash,
  IconSearch,
  IconClock,
  IconFilm,
  IconAlert,
  IconShield,
  IconGlobe,
  IconMonitor,
} from "@/components/icons";
import { useCapabilities } from "@/hooks/useCapabilities";
import { toast } from "@/components/Toast";

// The protocols a device can be reached over, with the port each answers on by
// convention.
//
// This list is deliberately short, and it mirrors the server's: the API and the
// database both reject anything outside it. Only protocols GuardRail can actually
// broker appear here. Offering FTP because it is "common" would let someone
// register a device, bind a credential to it, and discover only at Connect that
// nothing can open the session — a device that exists but can never be used is
// worse than one you were told not to add.
//
// Which cuts both ways: telnet was added to this list, to both server-side
// vocabularies and to a gateway, while the database CHECK that is the real
// gatekeeper still listed five protocols. Every layer agreed and the INSERT
// refused. Adding one here means adding it there too (see 0021_telnet_scheme).
//
// `hint` is what the operator is really choosing between: two of these are web
// UIs, the rest are not.
export const PROTOCOLS: { value: string; label: string; port: number; hint: string }[] = [
  { value: "https", label: "HTTPS", port: 443, hint: "Web UI, encrypted" },
  { value: "http", label: "HTTP", port: 80, hint: "Web UI, unencrypted" },
  { value: "ssh", label: "SSH", port: 22, hint: "Terminal session" },
  { value: "rdp", label: "RDP", port: 3389, hint: "Windows desktop" },
  { value: "vnc", label: "VNC", port: 5900, hint: "Remote desktop" },
  // The hint says cleartext because that is the thing an operator must weigh, and
  // the only honest reason to pick this over SSH is that the device cannot do SSH.
  { value: "telnet", label: "Telnet", port: 23, hint: "Legacy CLI, cleartext — prefer SSH" },
];

// isWebScheme mirrors the server's assets.IsWebScheme. Only a web device has a
// delivery mode to choose: a terminal or desktop device has one gateway and no
// choice, and the server refuses an isolated one.
export function isWebScheme(s: string): boolean {
  return s === "http" || s === "https";
}

// defaultPortFor returns the conventional port for a protocol.
export function defaultPortFor(proto: string): string {
  const p = PROTOCOLS.find((x) => x.value === proto);
  return p ? String(p.port) : "";
}

// The controlled device-type vocabulary offered in the add/edit form and used by
// the type filter. "Other" lets an operator type a free-form value — the field
// is free-form end to end, so anything is accepted; these are just the common
// managed-interface kinds.
export const DEVICE_TYPES = [
  "router",
  "firewall",
  "switch",
  "load-balancer",
  "access-point",
  "linux-server",
  "windows-server",
  "windows-pc",
  "hypervisor",
  "storage",
  "pdu",
];
const TYPE_LABEL: Record<string, string> = {
  "load-balancer": "Load balancer",
  "access-point": "Access point",
  "linux-server": "Linux server",
  "windows-server": "Windows server",
  "windows-pc": "Windows PC",
  pdu: "PDU",
};
export function deviceTypeLabel(t: string): string {
  if (!t) return "Device";
  return TYPE_LABEL[t] ?? t.charAt(0).toUpperCase() + t.slice(1);
}
function addedOn(iso?: string): string {
  const d = plausibleDate(iso);
  return d ? d.toLocaleDateString(undefined, { dateStyle: "medium" }) : "";
}

interface DeviceForm {
  name: string;
  host: string;
  port: string;
  scheme: string;
  vendor: string;
  device_type: string;
  verify_tls: boolean;
  allow_unmanaged: boolean;
  record_sessions: boolean;
  delivery_mode: string;
  idle_timeout_minutes: string;
}

const EMPTY_FORM: DeviceForm = {
  name: "",
  host: "",
  port: "443",
  scheme: "https",
  vendor: "",
  device_type: "firewall",
  verify_tls: false,
  allow_unmanaged: false,
  // Recording on by default: it is the posture you should get without having to
  // ask for it. Turning it off is the deliberate act.
  record_sessions: true,
  // Recording only exists under isolation, so the default follows from it.
  delivery_mode: "isolated",
  // An hour of inactivity ends the session. Kept as a string because it is a
  // text input; "" would post NaN, so the submit coerces it.
  idle_timeout_minutes: "60",
};

export function DevicesPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const canConnect = useAuth((s) => s.has("device:connect"));
  const canWrite = useAuth((s) => s.has("device:write"));
  const canBind = useAuth((s) => s.has("credential:write"));
  const [showCreate, setShowCreate] = useState(false);
  const [credentialFor, setCredentialFor] = useState<Device | null>(null);

  const { data, isLoading, isError } = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: async () => (await api.get<{ data: Device[] }>("/devices")).data.data,
  });

  const connect = useMutation({
    mutationFn: async (dev: Device) => {
      const res = (await api.post<ConnectResult>(`/devices/${dev.id}/connect`, {})).data;
      return { res, dev };
    },
    onSuccess: ({ res, dev }) => {
      if (res.session_id) {
        void qc.invalidateQueries({ queryKey: ["sessions", "active"] });
        navigate(`/sessions/${res.session_id}/view?name=${encodeURIComponent(dev.name)}`);
      }
    },
    onError: (err) => toast.error(problemDetail(err, "Connect failed")),
  });

  const remove = useMutation({
    mutationFn: async (id: string) => api.delete(`/devices/${id}`),
    onSuccess: () => {
      toast.success("Device removed");
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Delete failed")),
  });

  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  // Types are compared case-insensitively so pre-existing "Router"/"router"
  // variants collapse into one filter chip.
  const typesPresent = useMemo(
    () => Array.from(new Set((data ?? []).map((d) => (d.device_type || "").toLowerCase()).filter(Boolean))).sort(),
    [data],
  );
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data ?? []).filter((d) => {
      if (typeFilter !== "all" && (d.device_type || "").toLowerCase() !== typeFilter) return false;
      if (!q) return true;
      return (
        d.name.toLowerCase().includes(q) ||
        d.host.toLowerCase().includes(q) ||
        (d.vendor || "").toLowerCase().includes(q) ||
        (d.device_type || "").toLowerCase().includes(q)
      );
    });
  }, [data, typeFilter, search]);

  // These three partition the estate: every device is in exactly one. They are
  // the same question CredentialBadge answers, in the same order of precedence —
  // a bound credential is what a device HAS, break-glass is only what it falls
  // back on, so a device with both is credentialed and is not counted again.
  //
  // Counting break-glass as every allow_unmanaged device double-counted exactly
  // those, and the meter adds two of these percentages together: eight devices,
  // all credentialed, two of them also break-glass, read "125% managed".
  const total = data?.length ?? 0;
  const credentialed = data?.filter((d) => d.has_credential).length ?? 0;
  const breakGlass = data?.filter((d) => !d.has_credential && d.allow_unmanaged).length ?? 0;
  const needsCred = data?.filter((d) => !d.has_credential && !d.allow_unmanaged).length ?? 0;

  return (
    <div>
      <PageHero
        icon={IconDevices}
        eyebrow="Access"
        title="Devices"
        subtitle="Web management interfaces reachable through recorded, credential-injected sessions."
        actions={
          canWrite && (
            <button className="btn-primary" onClick={() => setShowCreate(true)}>
              <IconPlus size={16} /> Add device
            </button>
          )
        }
        stats={
          data && data.length > 0 ? (
            <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <StatCluster
                items={[
                  { label: "Devices", value: total },
                  {
                    label: "Credentialed",
                    value: credentialed,
                    tone: "success",
                  },
                  {
                    label: "Needs cred",
                    value: needsCred,
                    tone: needsCred > 0 ? "danger" : undefined,
                  },
                  { label: "Break-glass", value: breakGlass },
                ]}
              />
              <CoverageMeter credentialed={credentialed} breakGlass={breakGlass} needsCred={needsCred} total={total} />
            </div>
          ) : undefined
        }
      />

      {isLoading && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      )}
      {isError && <ErrorNote message="Failed to load devices" />}
      {data && data.length === 0 && (
        <EmptyState
          icon={IconDevices}
          title="No devices yet"
          message="Register a device to broker recorded, credential-injected access to its web UI."
          action={
            canWrite && (
              <button className="btn-primary" onClick={() => setShowCreate(true)}>
                <IconPlus size={16} /> Add device
              </button>
            )
          }
        />
      )}

      {data && data.length > 0 && (
        <>
          <DeviceFilterBar
            types={typesPresent}
            active={typeFilter}
            onType={setTypeFilter}
            search={search}
            onSearch={setSearch}
            total={data.length}
            shown={filtered.length}
          />
          {filtered.length === 0 ? (
            <EmptyState
              icon={IconSearch}
              title="No matching devices"
              message="No devices match the current type filter or search."
            />
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {filtered.map((d) => (
                <DeviceCard
                  key={d.id}
                  device={d}
                  canConnect={canConnect}
                  canBind={canBind}
                  canWrite={canWrite}
                  connecting={connect.isPending}
                  deleting={remove.isPending}
                  onOpen={() => navigate(`/devices/${d.id}`)}
                  onConnect={() => connect.mutate(d)}
                  onBind={() => setCredentialFor(d)}
                  onDelete={() => {
                    if (confirm(`Remove device "${d.name}"? This cannot be undone.`)) remove.mutate(d.id);
                  }}
                />
              ))}
            </div>
          )}
        </>
      )}

      {showCreate && (
        <CreateDeviceModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            toast.success("Device registered");
            void qc.invalidateQueries({ queryKey: ["devices"] });
          }}
        />
      )}
      {credentialFor && (
        <SetCredentialModal
          device={credentialFor}
          onClose={() => setCredentialFor(null)}
          onSaved={(msg) => {
            setCredentialFor(null);
            toast.success(msg);
          }}
        />
      )}
    </div>
  );
}

// Type-filter "navbar" + search: All plus a chip per device type present in the
// fleet, and a free-text search — both applied client-side over the loaded list.
function DeviceFilterBar({
  types,
  active,
  onType,
  search,
  onSearch,
  total,
  shown,
}: {
  types: string[];
  active: string;
  onType: (t: string) => void;
  search: string;
  onSearch: (v: string) => void;
  total: number;
  shown: number;
}) {
  const chips = ["all", ...types];
  return (
    <div className="mb-4 flex flex-col gap-3 rounded-xl border border-line bg-surface/50 p-2 sm:flex-row sm:items-center">
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1">
        {chips.map((t) => (
          <button
            key={t}
            onClick={() => onType(t)}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-medium transition",
              active === t
                ? "bg-accent-soft text-accent ring-1 ring-inset ring-accent/20"
                : "text-muted hover:bg-surface-2 hover:text-fg",
            )}
          >
            {t === "all" ? "All" : deviceTypeLabel(t)}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <div className="relative">
          <IconSearch size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <input
            className="input h-8 w-full pl-8 sm:w-56"
            placeholder="Search devices…"
            value={search}
            onChange={(e) => onSearch(e.target.value)}
          />
        </div>
        <span className="hidden whitespace-nowrap text-2xs text-faint sm:inline">
          {shown}/{total}
        </span>
      </div>
    </div>
  );
}

// A single segmented bar showing how much of the fleet is credential-managed.
function CoverageMeter({
  credentialed,
  breakGlass,
  needsCred,
  total,
}: {
  credentialed: number;
  breakGlass: number;
  needsCred: number;
  total: number;
}) {
  const pct = (n: number) => (total > 0 ? (n / total) * 100 : 0);
  // Rounded once, at the end. Rounding each share and then adding them lets two
  // half-percents become a whole one, so a fully managed estate can read 101%.
  const managed = Math.round(pct(credentialed + breakGlass));
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-2 w-44 overflow-hidden rounded-full bg-surface-3">
        <div className="h-full bg-success transition-[width] duration-500" style={{ width: `${pct(credentialed)}%` }} />
        <div className="h-full bg-info transition-[width] duration-500" style={{ width: `${pct(breakGlass)}%` }} />
        <div className="h-full bg-danger transition-[width] duration-500" style={{ width: `${pct(needsCred)}%` }} />
      </div>
      <span className="whitespace-nowrap text-2xs uppercase tracking-wider text-faint">{managed}% managed</span>
    </div>
  );
}

function CredentialBadge({ device }: { device: Device }) {
  if (device.has_credential)
    return (
      <Badge tone="success" dot>
        credential bound
      </Badge>
    );
  if (device.allow_unmanaged)
    return (
      <Badge tone="warn" dot>
        break-glass
      </Badge>
    );
  return (
    <Badge tone="danger" dot>
      no credential
    </Badge>
  );
}

function DeviceCard({
  device: d,
  canConnect,
  canBind,
  canWrite,
  connecting,
  deleting,
  onOpen,
  onConnect,
  onBind,
  onDelete,
}: {
  device: Device;
  canConnect: boolean;
  canBind: boolean;
  canWrite: boolean;
  connecting: boolean;
  deleting: boolean;
  onOpen: () => void;
  onConnect: () => void;
  onBind: () => void;
  onDelete: () => void;
}) {
  const blocked = !d.has_credential && !d.allow_unmanaged;
  const stop = (fn: () => void) => (e: MouseEvent) => {
    e.stopPropagation();
    fn();
  };
  return (
    <div
      onClick={onOpen}
      className="group relative flex cursor-pointer flex-col overflow-hidden rounded-xl card-grad p-4 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:shadow-md"
    >
      <div className="flex items-start gap-3">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
          <IconDevices size={20} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-fg transition group-hover:text-accent">{d.name}</span>
          </div>
          <div className="truncate text-xs text-faint">
            {deviceTypeLabel(d.device_type)}
            {d.vendor ? ` · ${d.vendor}` : ""}
          </div>
        </div>
        {/* One state indicator, not two: the badge carries the dot and the word. */}
        <DeviceStatusBadge device={d} />
      </div>

      <div className="mt-3 rounded-lg border border-line bg-surface-2/40 px-3 py-2 font-mono text-xs text-muted">
        {d.url}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <CredentialBadge device={d} />
        {!d.verify_tls && <Badge tone="neutral">TLS-skip</Badge>}
        {d.created_at && (
          <span className="ml-auto inline-flex items-center gap-1 text-2xs text-faint">
            <IconClock size={12} /> added {addedOn(d.created_at)}
          </span>
        )}
      </div>

      <div className="mt-4 flex items-center justify-end gap-2 border-t border-line pt-3">
        {canBind && (
          <button
            className="btn-subtle"
            onClick={stop(onBind)}
            title={d.has_credential ? "Edit credential" : "Set credential"}
          >
            <IconKey size={15} /> {d.has_credential ? "Credential" : "Set credential"}
          </button>
        )}
        {canWrite && (
          <button
            className="btn-subtle text-faint hover:text-danger"
            disabled={deleting}
            onClick={stop(onDelete)}
            aria-label="Remove device"
            title="Remove device"
          >
            <IconTrash size={15} />
          </button>
        )}
        {canConnect && (
          <button
            className="btn-primary"
            disabled={connecting || d.status !== "active" || blocked}
            title={blocked ? "Bind a credential before connecting (or enable break-glass on the device)" : undefined}
            onClick={stop(onConnect)}
          >
            <IconPlug size={15} /> Connect
          </button>
        )}
      </div>
    </div>
  );
}

function CreateDeviceModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [f, setF] = useState<DeviceForm>(EMPTY_FORM);
  const set = <K extends keyof DeviceForm>(k: K, v: DeviceForm[K]) => setF((s) => ({ ...s, [k]: v }));
  const [cred, setCred] = useState<CredState>(EMPTY_CRED);
  const patchCred = (p: Partial<CredState>) => setCred((s) => ({ ...s, ...p }));
  const [groupIDs, setGroupIDs] = useState<string[]>([]);

  const create = useMutation({
    mutationFn: async () =>
      api.post("/devices", {
        name: f.name,
        host: f.host,
        port: Number(f.port) || 0,
        scheme: f.scheme,
        vendor: f.vendor,
        device_type: f.device_type,
        verify_tls: f.verify_tls,
        allow_unmanaged: f.allow_unmanaged,
        record_sessions: f.record_sessions,
        delivery_mode: f.delivery_mode,
        idle_timeout_minutes: Number(f.idle_timeout_minutes) || 0,
        group_ids: groupIDs,
        // The device owns its credential: send it inline, but only when a secret
        // was entered. Username and password are optional.
        credential: cred.secret
          ? {
              username: cred.username,
              secret: cred.secret,
              injection: cred.injection,
            }
          : undefined,
      }),
    onSuccess: onCreated,
  });

  return (
    <Modal
      title="Add device"
      icon={IconDevices}
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={create.isPending || !f.name || !f.host}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Saving…" : "Register"}
          </button>
        </>
      }
    >
      {create.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(create.error, "Could not create device")} />
        </div>
      )}
      <Field label="Name">
        <input
          className="input"
          value={f.name}
          onChange={(e) => set("name", e.target.value)}
          placeholder="Edge Firewall"
        />
      </Field>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <Field label="Host / IP" hint="Do not include the port here.">
            <input
              className="input"
              value={f.host}
              onChange={(e) => set("host", e.target.value)}
              placeholder="10.200.10.1"
            />
          </Field>
        </div>
        <Field label="Port">
          <input
            className="input"
            inputMode="numeric"
            value={f.port}
            onChange={(e) => set("port", e.target.value)}
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
              // Picking a protocol fills in its usual port. Switching protocol
              // replaces the port even if it was typed by hand: the old value
              // belonged to the old protocol, and silently keeping 443 on an SSH
              // device produces a connection that times out for no visible reason.
              // The field stays editable for the non-standard cases.
              const next = e.target.value;
              setF((s) => ({
                ...s,
                scheme: next,
                port: defaultPortFor(next),
                // Isolation is a web-only mode; carrying it onto an SSH device
                // would post a combination the server refuses.
                delivery_mode: isWebScheme(next) ? s.delivery_mode : "proxy",
              }));
              // Likewise the credential: HTTP Basic auth cannot log into SSH, so
              // carrying the old method across a protocol change would post one
              // the server refuses (422).
              setCred((c) => ({ ...c, injection: defaultInjectionFor(next) }));
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
          {(() => {
            const known = DEVICE_TYPES.includes(f.device_type);
            return (
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
                    autoFocus
                  />
                )}
              </div>
            );
          })()}
        </Field>
      </div>
      <Field label="Vendor">
        <input
          className="input"
          value={f.vendor}
          onChange={(e) => set("vendor", e.target.value)}
          placeholder="Fortinet"
        />
      </Field>
      <Field label="Asset groups" hint="Roles can be scoped to a group, so membership decides who reaches this device.">
        <GroupPicker value={groupIDs} onChange={setGroupIDs} />
      </Field>

      <div className="mb-3 rounded-lg border border-line bg-surface-2/40 p-3">
        <div className="mb-1 flex items-center gap-2 text-sm font-medium text-fg">
          <IconKey size={15} className="text-accent" /> Credential
          <span className="rounded bg-surface-3/60 px-1.5 py-0.5 text-2xs font-normal uppercase tracking-wider text-faint">
            optional
          </span>
        </div>
        <p className="mb-3 text-xs text-muted">
          Injected server-side on every connection and never shown to users. Leave the password blank to register the
          device without one — you can add it later, or enable break-glass below.
        </p>
        <CredentialFields value={cred} onChange={patchCred} scheme={f.scheme} />
      </div>

      {isWebScheme(f.scheme) && (
        <DeliveryModeField
          value={f.delivery_mode}
          // Recording has no meaning under the proxy — it never sees pixels — so
          // choosing it turns recording off rather than letting the form post a
          // pair the server will refuse.
          onChange={(v) =>
            setF((s) => ({
              ...s,
              delivery_mode: v,
              record_sessions: v === "proxy" ? false : s.record_sessions,
            }))
          }
        />
      )}

      <RecordingToggle
        checked={f.record_sessions}
        // The converse, for the web only: recording a web device requires
        // isolation, so asking for it selects that too. An SSH session is
        // recorded by its own gateway as a transcript, with no browser involved.
        onChange={(v) =>
          setF((s) => ({
            ...s,
            record_sessions: v,
            delivery_mode: v && isWebScheme(s.scheme) ? "isolated" : s.delivery_mode,
          }))
        }
        hint="Only you or a super admin will be able to change this later."
      />

      <IdleTimeoutField value={f.idle_timeout_minutes} onChange={(v) => set("idle_timeout_minutes", v)} />

      <label className="mb-3 flex items-center gap-2 text-sm text-muted">
        <input type="checkbox" checked={f.verify_tls} onChange={(e) => set("verify_tls", e.target.checked)} />
        Verify TLS certificate (uncheck for self-signed management UIs)
      </label>
      <label className="flex items-start gap-2 text-sm text-muted">
        <input
          type="checkbox"
          className="mt-1"
          checked={f.allow_unmanaged}
          onChange={(e) => set("allow_unmanaged", e.target.checked)}
        />
        <span>
          Break-glass: allow connecting with <strong className="text-fg">no bound credential</strong>
          <span className="mt-0.5 block text-xs text-warn/80">
            Off by default. When off, GuardRail refuses to connect until a credential is bound, so users are never
            dropped at the device's own login page.
          </span>
        </span>
      </label>
    </Modal>
  );
}

/* IdleTimeoutField is how long a session to this device may sit unused before it
   is ended.

   It is separate from the session's granted window on purpose, and the copy says
   so: the window caps how long access can last, this caps how long it can sit
   unattended. A session abandoned five minutes into a two-hour grant is an open,
   credential-injected door for the remaining hour and fifty-five. */
export function IdleTimeoutField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const mins = Number(value);
  const off = value.trim() !== "" && mins === 0;
  const invalid = value.trim() === "" || Number.isNaN(mins) || mins < 0 || mins > 1440;
  return (
    <div className="mb-3 rounded-lg border border-line bg-surface-2/40 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-fg">
            <IconClock size={15} className="text-faint" />
            End session when idle
          </div>
          <p className="mt-1 text-xs text-muted">
            {off
              ? "Sessions to this device are never ended for being idle — only when their access window runs out."
              : `A session with no activity for ${mins || 0} minute${mins === 1 ? "" : "s"} is ended automatically.`}
          </p>
          {off && (
            <p className="mt-1.5 flex items-start gap-1.5 text-2xs text-warn">
              <IconAlert size={13} className="mt-px shrink-0" />
              <span>An abandoned session stays open, and logged in, until its access window expires.</span>
            </p>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <input
            className={cn("input w-20 text-center", invalid && "border-danger")}
            inputMode="numeric"
            aria-label="Idle timeout in minutes"
            value={value}
            onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 4))}
          />
          <span className="text-xs text-muted">min</span>
        </div>
      </div>
      {invalid && (
        <p className="mt-1.5 text-2xs text-danger">Enter a number of minutes between 0 and 1440 (0 = never).</p>
      )}
    </div>
  );
}

// The two ways a session reaches a device, and what an operator is actually
// choosing between. Ordered least to most contained.
const DELIVERY_MODES = [
  {
    value: "proxy",
    label: "Reverse proxy",
    icon: IconGlobe,
    blurb: "The device's own UI is re-served through GuardRail. Downloads and clipboard work.",
  },
  {
    value: "isolated",
    label: "Isolated browser",
    icon: IconShield,
    blurb: "A browser on the server renders the device and streams pixels. Nothing but images reaches the user.",
  },
] as const;

/* DeliveryModeField is how a session reaches the device. It is a real security
   boundary, not a performance setting, so both options state what the user gets
   and what they give up rather than naming a mechanism and leaving them to guess.

   The reverse proxy re-serves the device under a path prefix, and a single-page
   appliance UI (a FortiGate, most switch and hypervisor consoles) cannot survive
   that: its router, its absolute URLs and its service worker are all compiled
   against the origin's root. That failure looks like a blank page after a
   successful login, which is worth warning about here rather than leaving someone
   to debug it live. */
export function DeliveryModeField({
  value,
  onChange,
  disabled,
  hint,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  hint?: string;
}) {
  const caps = useCapabilities();
  // Only claim isolation is missing once the server has said so; while the query
  // is in flight `data` is undefined, and warning on that flashes on every load.
  const noIsolation = caps.data?.browser_isolation === false;
  return (
    <div className="mb-3 rounded-lg border border-line bg-surface-2/40 p-3">
      <div className="mb-2 flex items-center gap-2 text-sm font-medium text-fg">
        <IconMonitor size={15} className="text-faint" />
        How sessions reach this device
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {DELIVERY_MODES.map((m) => {
          const on = value === m.value;
          return (
            <button
              key={m.value}
              type="button"
              disabled={disabled}
              aria-pressed={on}
              onClick={() => onChange(m.value)}
              className={cn(
                "rounded-lg border p-2.5 text-left transition-colors",
                on ? "border-accent/40 bg-accent-soft/40" : "border-line bg-surface hover:border-line-strong",
                disabled && "cursor-not-allowed opacity-60",
              )}
            >
              <div className="flex items-center gap-2 text-xs font-medium text-fg">
                <m.icon size={14} className={on ? "text-accent" : "text-faint"} />
                {m.label}
              </div>
              <p className="mt-1 text-2xs text-muted">{m.blurb}</p>
            </button>
          );
        })}
      </div>
      {value === "proxy" && (
        <p className="mt-2 flex items-start gap-1.5 text-2xs text-muted">
          <IconAlert size={13} className="mt-px shrink-0 text-warn/70" />
          <span>
            Appliance consoles that are single-page apps (FortiGate and most switch, hypervisor and BMC UIs) often will
            not load through a path prefix — a successful login lands on a blank page. Use the isolated browser for
            those.
          </span>
        </p>
      )}
      {value === "isolated" && noIsolation && (
        <p className="mt-2 flex items-start gap-1.5 text-2xs text-warn">
          <IconAlert size={13} className="mt-px shrink-0" />
          <span>
            This server has no usable Chromium, so sessions will fall back to the reverse proxy. Ask an administrator to
            install Chromium on the GuardRail server.
          </span>
        </p>
      )}
      {hint && <p className="mt-2 text-2xs text-faint">{hint}</p>}
    </div>
  );
}

/* RecordingToggle is the device's session-recording policy. It reads as a
   statement of what will happen, because that is the decision being made — not
   a preference. `disabled` covers the case where the viewer may edit the device
   but not its recording policy. */
export function RecordingToggle({
  checked,
  onChange,
  disabled,
  hint,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  hint?: string;
}) {
  const caps = useCapabilities();
  // Only claim the server cannot record once we know it: while the query is in
  // flight, data is undefined, and warning on that would flash a scary message
  // on every page load.
  const unavailable = caps.data?.session_recording === false;
  return (
    <div
      className={cn(
        "mb-3 rounded-lg border p-3 transition-colors",
        checked ? "border-accent/25 bg-accent-soft/40" : "border-line bg-surface-2/40",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-fg">
            <IconFilm size={15} className={checked ? "text-accent" : "text-faint"} />
            Record sessions
          </div>
          <p className="mt-1 text-xs text-muted">
            {checked
              ? "Every session to this device is screen-recorded and replayable from Recordings."
              : "Sessions to this device are brokered and audited, but not screen-recorded."}
          </p>
          {/* Recording changes how the device is delivered, not just whether it
              is captured. Say so on the control that causes it, rather than
              letting an operator discover it when downloads stop working. */}
          {checked && (
            <p className="mt-1 text-2xs text-faint">
              Recorded sessions open in an isolated browser: the device is rendered on the server and streamed as
              pixels, so file transfer and clipboard are unavailable and the watermark cannot be removed.
            </p>
          )}
          {checked && unavailable && (
            <p className="mt-1.5 flex items-start gap-1.5 text-2xs text-warn">
              <IconAlert size={13} className="mt-px shrink-0" />
              <span>
                This server has browser isolation switched off, so nothing will actually be recorded. Sessions stay
                brokered and audited. Ask an administrator to enable isolation on the GuardRail server.
              </span>
            </p>
          )}
          {hint && <p className="mt-1 text-2xs text-faint">{hint}</p>}
        </div>
        <Switch checked={checked} onChange={onChange} disabled={disabled} label="Record sessions" />
      </div>
    </div>
  );
}

/* ---- Reusable inline credential fields ------------------------------------ */
interface CredState {
  injection: string;
  username: string;
  secret: string;
}
// Seeded for the form's default protocol (https). The protocol select
// re-defaults it whenever that changes.
const EMPTY_CRED: CredState = { injection: defaultInjectionFor("https"), username: "", secret: "" };

function CredentialFields({
  value,
  onChange,
  scheme,
  secretLabel,
  secretPlaceholder,
  secretHint,
}: {
  value: CredState;
  onChange: (patch: Partial<CredState>) => void;
  // The device's protocol. It decides which methods can authenticate it, so the
  // form offers only those — the server refuses the rest with a 422, and a
  // console that lets you pick one is a console that lies.
  scheme: string;
  secretLabel?: string;
  secretPlaceholder?: string;
  secretHint?: string;
}) {
  const methods = injectionMethodsFor(scheme);
  const active = methods.find((i) => i.value === value.injection);
  // Header injection carries everything in the secret; no username needed.
  const needsUser = value.injection !== "header";
  const isKey = value.injection === "ssh-key";
  return (
    <div className="space-y-3">
      {/* Only worth choosing when there is a choice. A desktop takes a password
          and nothing else, so a one-item dropdown is just a question with one
          answer. */}
      {methods.length > 1 && (
        <Field label="Injection method" hint={active?.hint}>
          <select className="input" value={value.injection} onChange={(e) => onChange({ injection: e.target.value })}>
            {methods.map((i) => (
              <option key={i.value} value={i.value}>
                {i.label}
              </option>
            ))}
          </select>
        </Field>
      )}
      {needsUser && (
        <Field
          label="Username"
          // Desktop only: a bare username is the usual reason RDP "logs in as the
          // wrong user" — Windows NLA tries the wrong domain, auth fails, and it
          // drops to the interactive login. Say the format that avoids it.
          hint={
            scheme === "rdp" || scheme === "vnc"
              ? "Local account: .\\Administrator · Domain account: DOMAIN\\user"
              : undefined
          }
        >
          <input
            className="input"
            value={value.username}
            onChange={(e) => onChange({ username: e.target.value })}
            placeholder={scheme === "rdp" ? ".\\Administrator" : "admin"}
            autoComplete="off"
          />
        </Field>
      )}
      <Field
        label={secretLabel ?? (isKey ? "Private key" : value.injection === "header" ? "Header value" : "Password / secret")}
        hint={secretHint ?? (methods.length === 1 ? active?.hint : undefined)}
      >
        {isKey ? (
          // A PEM key is multi-line and cannot be pasted into a password input
          // without losing its newlines — at which case it stops parsing, and the
          // gateway can only say the key is unusable, never why.
          <textarea
            className="input h-28 font-mono text-2xs"
            value={value.secret}
            onChange={(e) => onChange({ secret: e.target.value })}
            placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n…"}
            spellCheck={false}
            autoComplete="off"
          />
        ) : (
          <input
            className="input"
            type="password"
            value={value.secret}
            onChange={(e) => onChange({ secret: e.target.value })}
            placeholder={secretPlaceholder ?? (value.injection === "header" ? "Bearer eyJ…" : "••••••••")}
            autoComplete="new-password"
          />
        )}
      </Field>
    </div>
  );
}

// SetCredentialModal manages the single credential a device owns — create,
// replace, or remove — all under the device itself. It prefills the device's
// current username/injection (never the secret); leaving the password blank on
// an existing credential keeps it.
function SetCredentialModal({
  device,
  onClose,
  onSaved,
}: {
  device: Device;
  onClose: () => void;
  onSaved: (msg: string) => void;
}) {
  const qc = useQueryClient();
  const [cred, setCred] = useState<CredState>({ ...EMPTY_CRED, injection: defaultInjectionFor(device.scheme) });
  const patchCred = (p: Partial<CredState>) => setCred((s) => ({ ...s, ...p }));

  const detail = useQuery<Device>({
    queryKey: ["device", device.id],
    queryFn: async () => (await api.get<Device>(`/devices/${device.id}`)).data,
  });
  const existing: DeviceCredential | undefined = detail.data?.credential;

  useEffect(() => {
    if (!existing) return;
    // A stored method the protocol cannot use is possible — devices registered
    // before the console asked the protocol have one (an SSH server holding an
    // HTTP Basic credential, which fails at Connect). Showing it selected would
    // render a <select> with no matching option, i.e. a blank box. Fall back to
    // the protocol's default so opening this modal and saving repairs it.
    const usable = injectionMethodsFor(device.scheme).some((m) => m.value === existing.injection);
    setCred({
      injection: usable ? existing.injection : defaultInjectionFor(device.scheme),
      username: existing.username,
      secret: "",
    });
  }, [existing, device.scheme]);

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["devices"] });
    void qc.invalidateQueries({ queryKey: ["device", device.id] });
  };

  const save = useMutation({
    mutationFn: async () =>
      api.put(`/devices/${device.id}/credential`, {
        username: cred.username,
        secret: cred.secret, // blank keeps the current secret on the server
        injection: cred.injection,
      }),
    onSuccess: () => {
      invalidate();
      onSaved(existing ? "Credential updated" : "Credential set");
    },
  });

  const remove = useMutation({
    mutationFn: async () => api.delete(`/devices/${device.id}/credential`),
    onSuccess: () => {
      invalidate();
      onSaved("Credential removed");
    },
  });

  // A brand-new credential needs a secret; an existing one may be edited without
  // re-entering it.
  const canSave = !!existing || cred.secret.length > 0;

  return (
    <Modal
      title={`Credential — ${device.name}`}
      icon={IconKey}
      onClose={onClose}
      footer={
        <>
          {existing && (
            <button
              className="btn-danger mr-auto"
              disabled={remove.isPending}
              onClick={() => {
                if (window.confirm(`Remove the credential from "${device.name}"?`)) remove.mutate();
              }}
            >
              <IconTrash size={15} /> Remove
            </button>
          )}
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!canSave || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : existing ? "Save" : "Set credential"}
          </button>
        </>
      }
    >
      <p className="mb-4 text-sm text-muted">
        Injected server-side on every connection to this device and never shown to users.
        {existing && " Leave the password blank to keep the current one."}
      </p>
      {(save.isError || remove.isError) && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(save.error ?? remove.error, "Could not save credential")} />
        </div>
      )}
      {detail.isLoading ? (
        <Spinner />
      ) : (
        <CredentialFields
          value={cred}
          onChange={patchCred}
          scheme={device.scheme}
          secretPlaceholder={existing ? "•••••••• (unchanged)" : undefined}
        />
      )}
    </Modal>
  );
}
