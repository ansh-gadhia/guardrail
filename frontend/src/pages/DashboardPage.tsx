import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import { plausibleDate } from "@/lib/dates";
import type { AccessRequest, DashboardSummary, Device } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { ErrorNote, StatusBadge, Panel, EmptyState, Skeleton, Hairline, Badge, cn } from "@/components/ui";
import { Donut, Legend, PostureBar } from "@/components/charts";
import {
  IconDevices,
  IconSessions,
  IconUsers,
  IconAudit,
  IconKey,
  IconCheck,
  IconAlert,
  IconChevronRight,
  IconShield,
} from "@/components/icons";

export function DashboardPage() {
  const has = useAuth((st) => st.has);
  const isSuper = useAuth((st) => !!st.principal?.is_super_admin);
  const canDecide = isSuper || has("approval:decide");

  // Lifted to the page rather than owned by the band below, because the posture
  // headline has to agree with it. "Nothing needs you right now" printed directly
  // above an unreviewed emergency access is worse than either line alone.
  const pendingApprovals = useQuery<AccessRequest[]>({
    queryKey: ["access-requests", "pending"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?pending=true")).data.requests ?? [],
    enabled: canDecide,
    refetchInterval: 30_000,
  });
  const unreviewed = useQuery<AccessRequest[]>({
    queryKey: ["access-requests", "unreviewed"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?unreviewed=true")).data.requests ?? [],
    enabled: canDecide,
    refetchInterval: 60_000,
  });

  const summary = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: async () => (await api.get<DashboardSummary>("/dashboard/summary")).data,
  });
  const devices = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: async () => (await api.get<{ data: Device[] }>("/devices")).data.data,
  });

  if (summary.isLoading) return <DashboardSkeleton />;
  if (summary.isError || !summary.data) return <ErrorNote message="Couldn't load the dashboard. Try reloading." />;

  const s = summary.data;
  const dev = devices.data ?? [];
  const credentialed = dev.filter((d) => d.has_credential).length;
  const needsCred = dev.filter((d) => !d.has_credential && !d.allow_unmanaged).length;
  const breakGlass = dev.filter((d) => d.allow_unmanaged && !d.has_credential).length;

  const waiting = pendingApprovals.data ?? [];
  const toReview = unreviewed.data ?? [];

  // "Attention" = things an operator should act on now — derived from real state,
  // not an invented score. A request nobody has answered and an emergency nobody
  // has signed off are both somebody's job, so they count.
  const attention = needsCred + waiting.length + toReview.length;

  return (
    <div className="space-y-5">
      <PostureBand
        attention={attention}
        needsCred={needsCred}
        failedLogins={s.failed_logins_24h}
        activeSessions={s.active_sessions}
        devices={s.devices}
        users={s.users}
      />

      <ApprovalsBand waiting={waiting} toReview={toReview} />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="lg:col-span-7">
          <Panel title="Access activity" icon={IconAudit} actions={<TinyLink to="/audit">Audit log</TinyLink>}>
            {s.recent_activity.length === 0 ? (
              <EmptyState message="Privileged actions will appear here as they happen." />
            ) : (
              <ActivityRail activity={s.recent_activity} />
            )}
          </Panel>
        </div>

        <div className="space-y-5 lg:col-span-5">
          <Panel title="Fleet coverage" icon={IconDevices} actions={<TinyLink to="/devices">Devices</TinyLink>}>
            {devices.isLoading ? (
              <Skeleton className="h-40" />
            ) : dev.length === 0 ? (
              <EmptyState message="Register a device to start brokering access." />
            ) : (
              <FleetCoverage credentialed={credentialed} needsCred={needsCred} breakGlass={breakGlass} total={dev.length} />
            )}
          </Panel>

          <Panel title="Top devices by sessions" icon={IconSessions}>
            {s.top_devices.length === 0 ? (
              <EmptyState message="No sessions recorded yet." />
            ) : (
              <div className="space-y-3.5">
                {(() => {
                  const max = Math.max(...s.top_devices.map((d) => d.sessions), 1);
                  return s.top_devices.map((d) => (
                    <PostureBar key={d.device_id} label={d.name} value={d.sessions} max={max} sub={`${d.sessions}`} />
                  ));
                })()}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

/* ---- Posture band — the hero thesis ---------------------------------------- */
function PostureBand({
  attention,
  needsCred,
  failedLogins,
  activeSessions,
  devices,
  users,
}: {
  attention: number;
  needsCred: number;
  failedLogins: number;
  activeSessions: number;
  devices: number;
  users: number;
}) {
  const clear = attention === 0;
  return (
    <section className="relative overflow-hidden rounded-2xl border border-line bg-surface shadow-sm">
      <Hairline />
      <div className="pointer-events-none absolute -left-24 -top-28 h-72 w-72 rounded-full bg-accent/10 blur-3xl" />
      <div className="relative flex flex-col gap-6 p-6 lg:flex-row lg:items-center lg:justify-between">
        {/* Headline state */}
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-2xs font-semibold uppercase tracking-[0.16em] text-accent/90">
            <span className={cn("h-1.5 w-1.5 rounded-full", clear ? "bg-success" : "bg-warn")} />
            Access posture
          </div>
          <h1 className="mt-2 font-display text-3xl font-semibold tracking-tight text-fg">
            {clear ? "All clear" : `${attention} ${attention === 1 ? "item needs" : "items need"} attention`}
          </h1>
          <p className="mt-1.5 max-w-md text-sm text-muted">
            {clear
              ? "Every device is credential-managed. Sessions are brokered and recorded."
              : "Resolve these before they block access or leave a device unmanaged."}
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {needsCred > 0 && (
              <SignalChip to="/devices" tone="danger" icon={IconKey}>
                {needsCred} {needsCred === 1 ? "device needs" : "devices need"} a credential
              </SignalChip>
            )}
            {failedLogins > 0 && (
              <SignalChip to="/audit" tone="info" icon={IconAlert}>
                {failedLogins} failed {failedLogins === 1 ? "login" : "logins"} · 24h
              </SignalChip>
            )}
            {clear && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-success/25 bg-success/10 px-3 py-1 text-xs font-medium text-success">
                <IconCheck size={13} /> Nothing needs you right now
              </span>
            )}
          </div>
        </div>

        {/* Instrument cluster — secondary, dense, not four equal cards */}
        <div className="flex shrink-0 items-stretch divide-x divide-line rounded-xl border border-line bg-surface-2/40">
          <Gauge value={activeSessions} label="Active sessions" tone={activeSessions > 0 ? "accent" : undefined} />
          <Gauge value={devices} label="Devices" />
          <Gauge value={users} label="Users" />
        </div>
      </div>
    </section>
  );
}

function Gauge({ value, label, tone }: { value: number; label: string; tone?: "accent" }) {
  return (
    <div className="flex min-w-[6.5rem] flex-col items-center justify-center px-5 py-3 text-center">
      <div className={cn("font-display text-2xl font-semibold tabular-nums", tone === "accent" ? "text-accent" : "text-fg")}>
        {value}
      </div>
      <div className="mt-1 text-2xs uppercase tracking-wider text-faint">{label}</div>
    </div>
  );
}

function SignalChip({
  to,
  tone,
  icon: Icon,
  children,
}: {
  to: string;
  tone: "danger" | "warn" | "info";
  icon: typeof IconKey;
  children: ReactNode;
}) {
  const tones = {
    danger: "border-danger/25 bg-danger/10 text-danger hover:bg-danger/15",
    warn: "border-warn/25 bg-warn/10 text-warn hover:bg-warn/15",
    info: "border-info/25 bg-info/10 text-info hover:bg-info/15",
  }[tone];
  return (
    <Link
      to={to}
      className={cn("group inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition", tones)}
    >
      <Icon size={13} />
      {children}
      <IconChevronRight size={13} className="opacity-60 transition-transform group-hover:translate-x-0.5" />
    </Link>
  );
}

/* ---- Activity rail — the signature timeline -------------------------------- */
function ActivityRail({ activity }: { activity: { ts: string; actor: string; action: string; result: string }[] }) {
  const dot = (r: string) => {
    const v = r?.toLowerCase();
    if (v === "success") return "bg-success";
    if (v === "denied") return "bg-warn";
    return "bg-danger";
  };
  return (
    <ol className="relative space-y-1">
      {/* the rail */}
      <span className="absolute bottom-2 left-[7px] top-2 w-px bg-line" aria-hidden />
      {activity.slice(0, 9).map((a, i) => (
        <li key={i} className="relative flex items-center gap-3 rounded-lg py-1.5 pl-6 pr-2 transition hover:bg-surface-2/50">
          <span
            className={cn(
              "absolute left-0 top-1/2 h-[15px] w-[15px] -translate-y-1/2 rounded-full border-2 border-surface",
              dot(a.result),
            )}
          />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm">
              <span className="font-mono text-xs text-fg">{a.action}</span>
              <span className="text-faint"> · {a.actor || "system"}</span>
            </div>
          </div>
          <time className="shrink-0 font-mono text-2xs tabular-nums text-faint">{plausibleDate(a.ts)?.toLocaleTimeString() ?? "—"}</time>
          <StatusBadge value={a.result} />
        </li>
      ))}
    </ol>
  );
}

/* ---- Fleet coverage donut -------------------------------------------------- */
function FleetCoverage({
  credentialed,
  needsCred,
  breakGlass,
  total,
}: {
  credentialed: number;
  needsCred: number;
  breakGlass: number;
  total: number;
}) {
  const segments = [
    { value: credentialed, className: "text-success", label: "Credentialed" },
    { value: breakGlass, className: "text-info", label: "Break-glass" },
    { value: needsCred, className: "text-danger", label: "Needs credential" },
  ].filter((seg) => seg.value > 0);
  return (
    <div className="flex items-center gap-5">
      <Donut segments={segments} centerLabel={total} centerSub={total === 1 ? "device" : "devices"} />
      <div className="min-w-0 flex-1">
        <Legend
          items={[
            { label: "Credentialed", value: credentialed, className: "text-success" },
            { label: "Break-glass", value: breakGlass, className: "text-info" },
            { label: "Needs credential", value: needsCred, className: "text-danger" },
          ]}
        />
      </div>
    </div>
  );
}

function TinyLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium text-muted transition hover:text-accent"
    >
      {children}
      <IconChevronRight size={13} />
    </Link>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-5">
      <Skeleton className="h-40 rounded-2xl" />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <Skeleton className="h-96 lg:col-span-7" />
        <div className="space-y-5 lg:col-span-5">
          <Skeleton className="h-44" />
          <Skeleton className="h-44" />
        </div>
      </div>
    </div>
  );
}

// ApprovalsBand surfaces the two things that need a person, on the screen people
// actually land on.
//
// It renders nothing when there is nothing to do — a permanently-present empty
// panel is how a dashboard teaches people to stop reading it — and nothing at
// all for somebody who cannot decide anything.
function ApprovalsBand({ waiting, toReview }: { waiting: AccessRequest[]; toReview: AccessRequest[] }) {
  if (waiting.length === 0 && toReview.length === 0) return null;

  return (
    <Panel
      title="Waiting on you"
      icon={IconShield}
      subtitle="Access requests nobody has answered, and emergency access nobody has signed off"
      actions={<TinyLink to="/approvals">Approvals</TinyLink>}
    >
      <div className="space-y-2">
        {waiting.slice(0, 4).map((r) => (
          <Link
            key={r.id}
            to="/approvals"
            className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-surface-2/40 px-3 py-2.5 transition hover:border-line-strong"
          >
            <div className="min-w-0">
              <div className="text-sm text-fg">
                <span className="font-medium">{r.requester}</span>
                <span className="text-muted"> wants </span>
                <span className="font-medium">{r.device}</span>
              </div>
              <div className="mt-0.5 truncate text-xs text-muted">{r.reason}</div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {r.is_emergency && <Badge tone="danger">Emergency</Badge>}
              <Badge tone="warn">Decide</Badge>
            </div>
          </Link>
        ))}
        {waiting.length > 4 && (
          <div className="px-1 text-xs text-muted">and {waiting.length - 4} more waiting</div>
        )}
        {toReview.length > 0 && (
          <Link
            to="/approvals"
            className="flex items-center justify-between gap-3 rounded-lg border border-danger/30 bg-danger/5 px-3 py-2.5 transition hover:border-danger/50"
          >
            <div className="text-sm text-fg">
              {toReview.length} emergency {toReview.length === 1 ? "access" : "accesses"} taken without approval
            </div>
            <Badge tone="danger">Review</Badge>
          </Link>
        )}
      </div>
    </Panel>
  );
}
