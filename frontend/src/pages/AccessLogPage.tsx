import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { LoginSession, DashboardSummary } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, StatCluster, Panel, Badge, Button, ErrorNote, EmptyState, Skeleton, cn } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { toast } from "@/components/Toast";
import { IconActivity, IconMonitor, IconGlobe, IconClock, IconLogout, IconCheck, IconAlert } from "@/components/icons";

/* ---- time + client helpers -------------------------------------------------
   Everything here works on the UTC instant the API sends and renders in the
   viewer's own locale/timezone. There is no server- or app-level timezone: the
   wire is UTC, the browser localizes. Relative and countdown values are pure
   math on epoch millis, so they're timezone-agnostic by construction. */
function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
function until(iso: string): string {
  const diff = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(diff)) return "—";
  if (diff <= 0) return "expired";
  const m = Math.round(diff / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}
function absLocal(iso: string): string {
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return "—";
  return dt.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
// absExact is the value an investigator writes down: seconds included, and the
// zone named so a timestamp copied out of here still means something in a ticket
// read by someone in another country. Used on hover, where it costs no space.
//
// The fields are listed out rather than asked for as dateStyle/timeStyle. Those
// two are shorthands that ECMA-402 forbids combining with any explicit field —
// including timeZoneName — and it enforces that by THROWING TypeError, not by
// ignoring the option. Thrown from a render path it takes the whole page to the
// error boundary, which is exactly what it did here: every row called this, so
// the Access Log died on first paint.
//
// Wrapped as well, because a formatter that throws must never be able to cost
// the operator the page again. Same lesson as the MFA QR: format defensively at
// the boundary, degrade to something readable.
function absExact(iso: string): string {
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return "—";
  try {
    const local = dt.toLocaleString(undefined, {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    });
    return `${local}\nUTC: ${dt.toISOString()}`;
  } catch {
    return dt.toISOString();
  }
}
function parseUA(ua: string): { browser: string; os: string } {
  if (!ua) return { browser: "Unknown client", os: "" };
  let browser = "Browser";
  if (/edg/i.test(ua)) browser = "Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";
  else if (/curl/i.test(ua)) browser = "curl";
  else if (/go-http|python|okhttp|node|axios/i.test(ua)) browser = "API client";
  let os = "";
  if (/windows/i.test(ua)) os = "Windows";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ios/i.test(ua)) os = "iOS";
  else if (/mac os x|macintosh/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";
  return { browser, os };
}

interface AuditRow {
  ts: string;
  actor: string;
  action: string;
  ip: string;
  result: string;
  detail?: Record<string, unknown> | null;
}

// Machine reason codes → operator-readable text for a blocked/other attempt.
const REASONS: Record<string, string> = {
  account_locked: "account locked",
  inactive: "account inactive",
  throttled: "rate limited",
  refresh_reuse: "token reuse detected",
};

/* A sign-in attempt described by the STAGE it reached. Local sign-in is two
   factors in sequence — password, then (if enrolled) a TOTP/recovery code — and
   the audit stream records each stage as its own `auth.login` event with a
   distinct reason. That's what lets the log say "password was correct but the
   2FA code was wrong" instead of a flat "failed", and stops the password-cleared
   `mfa_challenge` step from masquerading as a completed sign-in. */
type Stage = "password" | "mfa";
interface AttemptView {
  tone: "success" | "danger" | "warn" | "neutral";
  badge: string;
  detail: string;
  stage?: Stage;
  icon: "check" | "alert" | "pending";
}

const CIRCLE: Record<AttemptView["tone"], string> = {
  success: "bg-success/10 text-success",
  danger: "bg-danger/10 text-danger",
  warn: "bg-warn/10 text-warn",
  neutral: "bg-surface-2 text-muted",
};

function describeAttempt(r: AuditRow): AttemptView {
  const result = (r.result || "").toLowerCase();
  const reason = typeof r.detail?.reason === "string" ? (r.detail.reason as string) : "";

  if (result === "success") {
    // Password cleared, but the second factor is still outstanding — NOT a sign-in.
    if (reason === "mfa_challenge")
      return { tone: "neutral", badge: "2FA pending", detail: "Password accepted — awaiting 2FA code", stage: "mfa", icon: "pending" };
    if (reason === "mfa_totp")
      return { tone: "success", badge: "signed in", detail: "Verified with authenticator (2FA)", stage: "mfa", icon: "check" };
    if (reason === "mfa_recovery")
      return { tone: "success", badge: "signed in", detail: "Verified with a recovery code", stage: "mfa", icon: "check" };
    return { tone: "success", badge: "signed in", detail: "Password verified", stage: "password", icon: "check" };
  }

  if (result === "denied")
    return { tone: "warn", badge: "blocked", detail: REASONS[reason] ?? reason ?? "blocked by policy", icon: "alert" };

  // Failures — name the exact stage that broke.
  if (reason === "mfa_bad_code")
    return { tone: "danger", badge: "2FA failed", detail: "Password correct · wrong 2FA code", stage: "mfa", icon: "alert" };
  if (reason === "bad_password")
    return { tone: "danger", badge: "failed", detail: "Wrong password", stage: "password", icon: "alert" };
  if (reason === "unknown_user")
    return { tone: "danger", badge: "failed", detail: "No such account", stage: "password", icon: "alert" };
  return { tone: "danger", badge: "failed", detail: REASONS[reason] ?? reason ?? "sign-in failed", icon: "alert" };
}

export function AccessLogPage() {
  const qc = useQueryClient();
  const principal = useAuth((s) => s.principal);
  const has = useAuth((s) => s.has);
  const [attemptFilter, setAttemptFilter] = useState<"all" | "failed">("all");

  const sessions = useQuery<LoginSession[]>({
    queryKey: ["auth", "sessions"],
    queryFn: async () => (await api.get<{ data: LoginSession[] }>("/auth/sessions")).data.data,
    refetchInterval: 10_000,
  });

  const summary = useQuery<DashboardSummary>({
    queryKey: ["dashboard"],
    queryFn: async () => (await api.get<DashboardSummary>("/dashboard/summary")).data,
  });

  // Recent sign-in history is the audit feed filtered to login events. Only
  // fetched when the operator can read the audit log.
  const recent = useQuery<AuditRow[]>({
    queryKey: ["auth", "signin-attempts"],
    queryFn: async () =>
      (await api.get<{ data: AuditRow[] }>("/audit", { params: { action: "auth.login", limit: 50 } })).data.data,
    enabled: has("log:read"),
    refetchInterval: 20_000,
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => api.post(`/auth/sessions/${id}/revoke`, {}),
    onSuccess: () => {
      toast.success("Session signed out");
      void qc.invalidateQueries({ queryKey: ["auth", "sessions"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Couldn't sign that session out")),
  });

  const rows = sessions.data ?? [];
  const stats = useMemo(() => {
    const users = new Set(rows.map((r) => r.user_id));
    const ips = new Set(rows.map((r) => r.ip).filter(Boolean));
    return { active: rows.length, users: users.size, ips: ips.size };
  }, [rows]);

  const onRevoke = (s: LoginSession) => {
    const msg = s.current
      ? "Sign out this session? You'll be returned to the login screen."
      : s.self
        ? "Sign out this other session of yours?"
        : `Sign out ${s.email}? They'll have to sign in again.`;
    if (window.confirm(msg)) revoke.mutate(s.id);
  };

  const columns: Column<LoginSession>[] = [
    {
      key: "user",
      header: "User",
      value: (s) => s.email,
      cell: (s) => (
        <div className="flex items-center gap-2">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full accent-grad text-2xs font-semibold text-white ring-1 ring-white/20">
            {s.email.slice(0, 2).toUpperCase()}
          </span>
          <span className="truncate font-medium text-fg">{s.email}</span>
          {s.current ? (
            <Badge tone="accent" dot>this device</Badge>
          ) : s.self ? (
            <Badge tone="neutral">you</Badge>
          ) : null}
        </div>
      ),
    },
    {
      key: "client",
      header: "Client",
      value: (s) => parseUA(s.user_agent).browser,
      cell: (s) => {
        const ua = parseUA(s.user_agent);
        return (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-muted">
            <IconMonitor size={14} className="shrink-0 text-faint" />
            {ua.browser}
            {ua.os && <span className="text-faint">· {ua.os}</span>}
          </span>
        );
      },
    },
    {
      key: "ip",
      header: "IP address",
      value: (s) => s.ip,
      cell: (s) => (
        <span className="inline-flex items-center gap-1.5 font-mono text-xs text-fg">
          <IconGlobe size={13} className="text-faint" />
          {s.ip || "—"}
        </span>
      ),
    },
    {
      key: "signed_in",
      header: "Signed in",
      value: (s) => s.signed_in_at,
      cell: (s) => (
        <div className="leading-tight" title={absExact(s.signed_in_at)}>
          <div className="whitespace-nowrap text-sm text-fg">{absLocal(s.signed_in_at)}</div>
          <div className="text-2xs text-faint">{relTime(s.signed_in_at)}</div>
        </div>
      ),
    },
    {
      key: "last_seen",
      header: "Last active",
      value: (s) => s.last_seen_at,
      // Both, like "Signed in" above: the relative form is what the eye scans for
      // "is this happening now", the absolute is what an investigation cites. A
      // relative time alone is also the one that rots — a page left open all
      // afternoon still says "2m ago".
      cell: (s) => (
        <div className="leading-tight" title={absExact(s.last_seen_at)}>
          <div className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-muted">
            <IconClock size={13} className="text-faint" />
            {absLocal(s.last_seen_at)}
          </div>
          <div className="text-2xs text-faint">{relTime(s.last_seen_at)}</div>
        </div>
      ),
    },
    {
      key: "expires",
      header: "Expires",
      value: (s) => s.expires_at,
      cell: (s) => <span className="font-mono text-xs tabular-nums text-muted">{until(s.expires_at)}</span>,
      align: "right",
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      align: "right",
      cell: (s) => (
        <Button
          size="sm"
          variant={s.current ? "ghost" : "subtle"}
          icon={IconLogout}
          disabled={revoke.isPending}
          onClick={(e) => {
            e.stopPropagation();
            onRevoke(s);
          }}
        >
          {s.current ? "Sign out" : "Revoke"}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <PageHero
        icon={IconActivity}
        eyebrow="Governance"
        title="Access Log"
        subtitle="Who is signed in to the console right now — from where, since when, and on what."
        stats={
          rows.length > 0 ? (
            <StatCluster
              items={[
                { label: "Active sessions", value: stats.active, tone: "accent" },
                { label: "Signed-in users", value: stats.users },
                { label: "Unique IPs", value: stats.ips },
                {
                  label: "Failed · 24h",
                  value: summary.data?.failed_logins_24h ?? 0,
                  tone: (summary.data?.failed_logins_24h ?? 0) > 0 ? "warn" : undefined,
                },
              ]}
            />
          ) : undefined
        }
      />

      <Panel title="Active sessions" icon={IconMonitor} bodyClassName="p-0">
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : sessions.isError ? (
          <div className="p-4">
            <ErrorNote message="Couldn't load active sessions. Try reloading." />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No active sessions" message="Live console sign-ins will appear here." />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(s) => s.id}
            searchable
            searchPlaceholder="Search by user, IP, or client…"
            pageSize={12}
            exportName="access-log"
          />
        )}
      </Panel>

      {has("log:read") && (
        <Panel
          title="Sign-in attempts"
          icon={IconActivity}
          actions={
            <div className="flex items-center gap-0.5 rounded-lg border border-line bg-surface-2/60 p-0.5 text-xs">
              {(["all", "failed"] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setAttemptFilter(f)}
                  className={cn(
                    "rounded-md px-2.5 py-1 font-medium capitalize transition",
                    attemptFilter === f ? "bg-surface text-accent shadow-xs ring-1 ring-line" : "text-muted hover:text-fg",
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          }
        >
          {recent.isLoading ? (
            <Skeleton className="h-40" />
          ) : (
            (() => {
              const items = (recent.data ?? []).filter(
                (r) => attemptFilter === "all" || (r.result || "").toLowerCase() !== "success",
              );
              if (items.length === 0)
                return (
                  <EmptyState
                    message={attemptFilter === "failed" ? "No failed sign-in attempts — all clear." : "No sign-in events recorded yet."}
                  />
                );
              return (
                <ol className="divide-y divide-line">
                  {items.map((r, i) => {
                    const a = describeAttempt(r);
                    const Icon = a.icon === "check" ? IconCheck : a.icon === "pending" ? IconClock : IconAlert;
                    return (
                      <li key={i} className="flex items-center gap-3 py-2.5">
                        <span className={cn("grid h-6 w-6 shrink-0 place-items-center rounded-full", CIRCLE[a.tone])}>
                          <Icon size={13} />
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate text-sm text-fg">{r.actor || "unknown account"}</span>
                            {a.stage && a.tone !== "success" && (
                              <span className="shrink-0 rounded border border-line px-1 py-px font-mono text-[10px] uppercase leading-none tracking-wide text-faint">
                                {a.stage === "mfa" ? "2FA" : "Password"}
                              </span>
                            )}
                          </div>
                          <div className="text-2xs text-faint">{a.detail}</div>
                        </div>
                        <span className="hidden font-mono text-xs text-faint sm:inline">{r.ip || "—"}</span>
                        <Badge tone={a.tone}>{a.badge}</Badge>
                        {/* dateTime carries the machine-readable instant; the two
                            rendered lines are for people. A sign-in attempt is the
                            thing most likely to be quoted in an incident report,
                            so the date has to be here and not only on hover. */}
                        {/* spans, not divs: <time> takes phrasing content only,
                            and a <div> inside it is invalid markup React will
                            warn about on every render. */}
                        <time
                          dateTime={r.ts}
                          title={absExact(r.ts)}
                          className="w-32 shrink-0 text-right leading-tight tabular-nums"
                        >
                          <span className="block whitespace-nowrap text-2xs text-muted">{absLocal(r.ts)}</span>
                          <span className="block font-mono text-2xs text-faint">{relTime(r.ts)}</span>
                        </time>
                      </li>
                    );
                  })}
                </ol>
              );
            })()
          )}
        </Panel>
      )}

      {principal && rows.length > 0 && (
        <p className="px-1 text-2xs text-faint">
          Times are shown in your local timezone. Revoking a session signs that browser out immediately.
        </p>
      )}
    </div>
  );
}
