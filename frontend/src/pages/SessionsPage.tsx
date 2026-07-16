import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import type { Session, Device, UserRow } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, ErrorNote, EmptyState, StatusBadge, Badge, Skeleton } from "@/components/ui";
import { IconSessions, IconPlug, IconTrash, IconClock, IconGlobe, IconUsers, IconMonitor } from "@/components/icons";
import { toast } from "@/components/Toast";

/* Sessions carry raw user_id/device_id + client_ip/user_agent; we resolve the
   ids to names via the same /devices + /users lookups the Recordings page uses,
   so a live session reads as "who reached what from where", not a bare UUID. */
function parseUA(ua?: string): string {
  if (!ua) return "";
  let b = "Browser";
  if (/edg/i.test(ua)) b = "Edge";
  else if (/chrome|crios/i.test(ua)) b = "Chrome";
  else if (/firefox|fxios/i.test(ua)) b = "Firefox";
  else if (/safari/i.test(ua)) b = "Safari";
  else if (/curl/i.test(ua)) b = "curl";
  else if (/go-http|python|okhttp|node|axios/i.test(ua)) b = "API client";
  let os = "";
  if (/windows/i.test(ua)) os = "Windows";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ios/i.test(ua)) os = "iOS";
  else if (/mac os x|macintosh/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";
  return os ? `${b} · ${os}` : b;
}
function expiresIn(iso?: string): string {
  if (!iso) return "";
  const diff = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(diff)) return "";
  if (diff <= 0) return "expired";
  const m = Math.round(diff / 60000);
  return m < 60 ? `${m}m left` : `${Math.round(m / 60)}h left`;
}

export function SessionsPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const has = useAuth((s) => s.has);
  const canTerminate = has("session:terminate");

  const { data, isLoading, isError } = useQuery<Session[]>({
    queryKey: ["sessions", "active"],
    queryFn: async () => (await api.get<{ data: Session[] }>("/sessions/active")).data.data,
    refetchInterval: 5000,
  });
  const devices = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: async () => (await api.get<{ data: Device[] }>("/devices")).data.data,
    enabled: has("device:read"),
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

  const terminate = useMutation({
    mutationFn: async (id: string) => api.post(`/sessions/${id}/terminate`, {}),
    onSuccess: () => {
      toast.success("Session terminated");
      void qc.invalidateQueries({ queryKey: ["sessions", "active"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Terminate failed")),
  });

  return (
    <div>
      <PageHero
        icon={IconSessions}
        eyebrow="Access"
        title="Active Sessions"
        subtitle="Live brokered access sessions — auto-refreshing every 5 seconds."
        actions={<Badge tone="success" dot>live</Badge>}
      />
      {isLoading && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
      )}
      {isError && <ErrorNote message="Failed to load sessions" />}
      {data && data.length === 0 && (
        <EmptyState icon={IconSessions} title="No active sessions" message="Brokered sessions appear here while they are live." />
      )}

      {data && data.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {data.map((s) => {
            const dname = deviceName.get(s.device_id) ?? s.device_name ?? "";
            const uemail = userEmail.get(s.user_id ?? "") ?? s.user_email ?? "";
            const client = parseUA(s.user_agent);
            const exp = expiresIn(s.granted_until);
            return (
            <div
              key={s.id}
              className="group relative flex flex-col overflow-hidden rounded-xl card-grad p-4 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:shadow-md"
            >
              <div className="flex items-start gap-3">
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-success/12 text-success ring-1 ring-inset ring-success/20">
                  <IconSessions size={20} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-fg">{dname || "Unknown device"}</div>
                  <div className="truncate font-mono text-2xs text-faint">{s.device_id.slice(0, 8)}…</div>
                </div>
                <StatusBadge value={s.status} />
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-1.5">
                <Badge tone="neutral">{s.protocol?.toUpperCase()}</Badge>
                <span className="inline-flex items-center gap-1 text-xs text-faint">
                  <IconClock size={13} />
                  {s.created_at ? new Date(s.created_at).toLocaleTimeString() : "—"}
                </span>
                {exp && <span className="text-2xs text-faint">· {exp}</span>}
              </div>

              <div className="mt-3 space-y-1.5 text-xs">
                <div className="flex items-center gap-1.5 text-muted">
                  <IconUsers size={13} className="shrink-0 text-faint" />
                  {uemail ? (
                    <span className="truncate">{uemail}</span>
                  ) : (
                    <span className="truncate font-mono text-faint">{(s.user_id ?? "").slice(0, 8) || "unknown user"}</span>
                  )}
                </div>
                {client && (
                  <div className="flex items-center gap-1.5 text-muted">
                    <IconMonitor size={13} className="shrink-0 text-faint" />
                    <span className="truncate">{client}</span>
                  </div>
                )}
                <div className="flex items-center gap-1.5 text-muted">
                  <IconGlobe size={13} className="shrink-0 text-faint" />
                  {s.client_ip ? (
                    <>
                      <span className="rounded-md border border-line bg-surface-2/60 px-1.5 py-0.5 font-mono text-2xs text-fg">
                        {s.client_ip}
                      </span>
                      <span className="text-faint">source IP</span>
                    </>
                  ) : (
                    <span className="text-faint">source IP unavailable</span>
                  )}
                </div>
              </div>

              <div className="mt-4 flex items-center justify-end gap-2 border-t border-line pt-3">
                {canTerminate && (
                  <button
                    className="btn-subtle text-faint hover:text-danger"
                    disabled={terminate.isPending}
                    onClick={() => {
                      if (window.confirm(`Terminate the session on "${dname || "this device"}"?`)) terminate.mutate(s.id);
                    }}
                  >
                    <IconTrash size={15} /> Terminate
                  </button>
                )}
                {s.status === "active" && (
                  <button
                    className="btn-primary"
                    onClick={() => navigate(`/sessions/${s.id}/view?name=${encodeURIComponent(dname || "session")}`)}
                  >
                    <IconPlug size={15} /> Open
                  </button>
                )}
              </div>
            </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
