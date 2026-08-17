import { Fragment, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { UserRow, Role, Permission, RoleDeviceAccess, AssetGroup } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, ErrorNote, EmptyState, Modal, Field, StatCluster, Badge, Skeleton, Spinner, Tabs, Input, Button, cn } from "@/components/ui";
import { IconUsers, IconPlus, IconTrash, IconShield, IconLock, IconCheck, IconMinus, IconSliders, IconAudit, IconDevices, IconFolder, IconGlobe, IconKey, IconAlert, IconClipboard } from "@/components/icons";
import { toast } from "@/components/Toast";
import { AccountsAdmin } from "@/components/AccountsAdmin";
import { PasswordStrength, scorePassword } from "@/components/PasswordStrength";
import { DEVICE_TYPES, deviceTypeLabel } from "./DevicesPage";

export function AccessPage() {
  const qc = useQueryClient();
  const me = useAuth((s) => s.principal);
  const canWrite = useAuth((s) => s.has("user:write"));
  const canBindCredentials = useAuth((s) => s.has("credential:write"));
  const [showCreate, setShowCreate] = useState(false);
  const [editRolesFor, setEditRolesFor] = useState<UserRow | null>(null);
  const [resetFor, setResetFor] = useState<UserRow | null>(null);
  const [editAccessFor, setEditAccessFor] = useState<Role | null>(null);

  const users = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data,
  });
  const roles = useQuery<Role[]>({
    queryKey: ["roles"],
    queryFn: async () => (await api.get<{ data: Role[] }>("/roles")).data.data,
  });

  const remove = useMutation({
    mutationFn: async (id: string) => api.delete(`/users/${id}`),
    onSuccess: () => {
      toast.success("User removed");
      void qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Delete failed")),
  });

  const perms = useQuery<Permission[]>({
    queryKey: ["permissions"],
    queryFn: async () => (await api.get<{ data: Permission[] }>("/permissions")).data.data,
  });
  const [tab, setTab] = useState<"members" | "roles" | "accounts">("members");

  const userCount = users.data?.length ?? 0;
  const superCount = users.data?.filter((u) => u.is_super_admin).length ?? 0;
  const roleCount = roles.data?.length ?? 0;
  const permCount = perms.data?.length ?? 0;

  return (
    <div>
      <PageHero
        icon={IconShield}
        eyebrow="Governance"
        title="Access Control"
        subtitle="Members, the roles assigned to them, and exactly what each role can do."
        actions={
          canWrite &&
          tab === "members" && (
            <button className="btn-primary" onClick={() => setShowCreate(true)}>
              <IconPlus size={16} /> Add user
            </button>
          )
        }
        stats={
          <StatCluster
            items={[
              { label: "Members", value: userCount },
              { label: "Super admins", value: superCount, tone: superCount > 1 ? "warn" : undefined },
              { label: "Roles", value: roleCount },
              { label: "Permissions", value: permCount, tone: "accent" },
            ]}
          />
        }
      />

      <div className="mb-5">
        <Tabs
          tabs={[
            { id: "members", label: "Members", icon: IconUsers },
            { id: "roles", label: "Roles & Permissions", icon: IconSliders },
            ...(canBindCredentials ? [{ id: "accounts", label: "Per-user accounts", icon: IconKey }] : []),
          ]}
          active={tab}
          onChange={(t) => setTab(t as "members" | "roles" | "accounts")}
        />
      </div>

      {tab === "members" ? (
        <>
          {users.isLoading && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-28" />
              ))}
            </div>
          )}
          {users.isError && <ErrorNote message="Failed to load users" />}
          {users.data && users.data.length === 0 && <EmptyState icon={IconUsers} message="No users found." />}
          {users.data && users.data.length > 0 && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {users.data.map((u) => (
                <div key={u.user_id} className="group relative flex flex-col overflow-hidden rounded-xl card-grad p-4 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:shadow-md">
                  <div className="flex items-start gap-3">
                    <span className="grid h-10 w-10 shrink-0 place-items-center rounded-full accent-grad text-xs font-semibold text-white shadow-sm ring-1 ring-white/20">
                      {u.email.slice(0, 2).toUpperCase()}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium text-fg">{u.email}</div>
                      <div className="truncate text-xs text-faint">{u.username || "—"}</div>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {u.is_super_admin ? (
                      <>
                        <Badge tone="accent">Super Admin</Badge>
                        {u.is_bootstrap_admin && <Badge tone="neutral">installation account</Badge>}
                      </>
                    ) : u.roles.length ? (
                      u.roles.map((r) => (
                        <Badge key={r} tone="neutral">
                          {r}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-faint">no roles</span>
                    )}
                  </div>
                  {canWrite && (
                    <div className="mt-4 flex items-center justify-end gap-2 border-t border-line pt-3">
                      {u.is_bootstrap_admin ? (
                        /* Say WHY rather than hiding the controls. A missing button
                           sends somebody hunting for a permission they already have;
                           this account is refused to everyone, including them. */
                        <span
                          className="flex items-center gap-1.5 text-xs text-faint"
                          title="This is the account GuardRail was installed with. It is how you get back in if every other administrator is lost, so its roles cannot be changed and it cannot be removed — by anyone. Replace it with `guardrail seed-admin` on the server."
                        >
                          <IconLock size={13} /> Installation account — locked
                        </span>
                      ) : (
                        <>
                          <button className="btn-subtle" onClick={() => setEditRolesFor(u)}>
                            Edit roles
                          </button>
                          <button className="btn-subtle" onClick={() => setResetFor(u)}>
                            Reset password
                          </button>
                          {u.user_id !== me?.user_id && (
                            <button
                              className="btn-subtle text-faint hover:text-danger"
                              disabled={remove.isPending}
                              aria-label={`Remove user ${u.email}`}
                              title="Remove user"
                              onClick={() => {
                                if (window.confirm(`Remove user "${u.email}"?`)) remove.mutate(u.user_id);
                              }}
                            >
                              <IconTrash size={15} />
                            </button>
                          )}
                        </>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      ) : tab === "accounts" ? (
        <AccountsAdmin />
      ) : (
        <RolesAndPermissions roles={roles} perms={perms} editAccessFor={editAccessFor} onEditAccess={setEditAccessFor} />
      )}

      {resetFor && (
        <ResetPasswordModal user={resetFor} onClose={() => setResetFor(null)} />
      )}

      {showCreate && roles.data && (
        <CreateUserModal
          roles={roles.data}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            toast.success("User created");
            void qc.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}
      {editRolesFor && roles.data && (
        <EditRolesModal
          user={editRolesFor}
          roles={roles.data}
          onClose={() => setEditRolesFor(null)}
          onSaved={() => {
            setEditRolesFor(null);
            toast.success("Roles updated");
            void qc.invalidateQueries({ queryKey: ["users"] });
          }}
        />
      )}
    </div>
  );
}

/* ---- Roles & Permissions ---------------------------------------------------- */
const RESOURCE_LABELS: Record<string, string> = {
  device: "Devices",
  credential: "Credentials",
  session: "Sessions",
  user: "Users",
  role: "Roles",
  org: "Organizations",
  group: "Asset groups",
  audit: "Audit",
  log: "Logs",
  recording: "Recordings",
};
const resourceLabel = (res: string) => RESOURCE_LABELS[res] ?? res.charAt(0).toUpperCase() + res.slice(1);
// The Super Admin role bypasses permission checks entirely (it carries no
// explicit grants), so it reads as full access everywhere.
const isSuperRole = (r: Role) => r.name.toLowerCase().includes("super");

// A role's visual identity — an icon + a tone — so each role is recognizable at
// a glance across cards, the matrix header, and the members list. Tones are
// intentional (by privilege), not a rainbow.
type Tone = "accent" | "info" | "warn" | "neutral";
function roleIdentity(r: Role): { icon: typeof IconShield; tone: Tone } {
  const n = r.name.toLowerCase();
  if (isSuperRole(r) || n.includes("admin")) return { icon: IconShield, tone: "accent" };
  if (n.includes("operator")) return { icon: IconSliders, tone: "info" };
  if (n.includes("audit")) return { icon: IconAudit, tone: "warn" };
  return { icon: IconLock, tone: "neutral" };
}
const TONE_TILE: Record<Tone, string> = {
  accent: "bg-accent-soft text-accent ring-accent/20",
  info: "bg-info/12 text-info ring-info/25",
  warn: "bg-warn/12 text-warn ring-warn/25",
  neutral: "bg-surface-3/70 text-muted ring-line",
};

type PermGroup = [string, Permission[]];

function RolesAndPermissions({
  roles,
  perms,
  editAccessFor,
  onEditAccess,
}: {
  roles: { data?: Role[]; isLoading: boolean; isError: boolean };
  perms: { data?: Permission[]; isLoading: boolean };
  editAccessFor: Role | null;
  onEditAccess: (r: Role | null) => void;
}) {
  const qc = useQueryClient();
  const canWriteRoles = useAuth((s) => s.has("role:write"));
  const [rankFor, setRankFor] = useState<Role | null>(null);
  if (roles.isLoading || perms.isLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }
  if (roles.isError || !roles.data) return <ErrorNote message="Failed to load roles" />;

  // Most-privileged roles first, so the matrix reads left-to-right by power.
  const roleList = [...roles.data].sort(
    (a, b) => (isSuperRole(b) ? 999 : b.permissions.length) - (isSuperRole(a) ? 999 : a.permissions.length),
  );

  const grouped = new Map<string, Permission[]>();
  for (const p of [...(perms.data ?? [])].sort((a, b) => a.key.localeCompare(b.key))) {
    const res = p.key.split(":")[0];
    if (!grouped.has(res)) grouped.set(res, []);
    grouped.get(res)!.push(p);
  }
  const groups: PermGroup[] = [...grouped.entries()].sort((a, b) => resourceLabel(a[0]).localeCompare(resourceLabel(b[0])));
  const totalPerms = perms.data?.length ?? 0;
  const roleHas = (r: Role, key: string) => isSuperRole(r) || r.permissions.includes(key);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {roleList.map((r) => (
          <RoleSummaryCard
            key={r.id}
            role={r}
            groups={groups}
            total={totalPerms}
            onEditAccess={canWriteRoles ? () => onEditAccess(r) : undefined}
            onEditRank={canWriteRoles ? () => setRankFor(r) : undefined}
          />
        ))}
      </div>

      {rankFor && (
        <ApprovalRankEditor
          role={rankFor}
          onClose={() => setRankFor(null)}
          onSaved={() => {
            setRankFor(null);
            toast.success("Approval rank updated");
            void qc.invalidateQueries({ queryKey: ["roles"] });
            void qc.invalidateQueries({ queryKey: ["approval-coverage"] });
          }}
        />
      )}

      {editAccessFor && (
        <DeviceAccessEditor
          role={editAccessFor}
          onClose={() => onEditAccess(null)}
          onSaved={() => {
            onEditAccess(null);
            toast.success("Device access updated");
            void qc.invalidateQueries({ queryKey: ["roles"] });
          }}
        />
      )}

      <div className="overflow-hidden rounded-xl border border-line bg-surface shadow-sm">
        <div className="border-b border-line bg-surface-2/50 px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-fg">
            <IconSliders size={16} className="text-accent" /> Permission matrix
          </div>
          <p className="mt-0.5 text-xs text-muted">
            Every permission and the roles that grant it. Super Admin bypasses checks (full access).
          </p>
        </div>
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead className="sticky top-0 z-20">
              <tr>
                <th className="sticky left-0 z-30 min-w-[15rem] border-b border-line bg-surface-2 px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-faint">
                  Permission
                </th>
                {roleList.map((r) => {
                  const id = roleIdentity(r);
                  return (
                    <th
                      key={r.id}
                      className="min-w-[8rem] border-b border-l border-line bg-surface-2 px-3 py-3 text-center align-bottom"
                    >
                      <div className="flex flex-col items-center gap-1.5">
                        <span className={cn("grid h-7 w-7 place-items-center rounded-lg ring-1 ring-inset", TONE_TILE[id.tone])}>
                          <id.icon size={15} />
                        </span>
                        <div className="max-w-[7.5rem] truncate text-xs font-semibold text-fg" title={r.name}>
                          {r.name}
                        </div>
                        <div className="text-2xs font-normal normal-case tracking-normal text-faint">
                          {isSuperRole(r) ? "full access" : `${r.permissions.length}/${totalPerms}`}
                        </div>
                      </div>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {groups.map(([res, ps]) => (
                <Fragment key={res}>
                  <tr>
                    <td
                      colSpan={roleList.length + 1}
                      className="sticky left-0 bg-surface-2/60 px-4 py-1.5 text-2xs font-semibold uppercase tracking-wider text-accent/90 backdrop-blur"
                    >
                      {resourceLabel(res)}
                    </td>
                  </tr>
                  {ps.map((p) => (
                    <tr key={p.key} className="group/row border-b border-line/60 transition hover:bg-surface-2/40">
                      <td className="sticky left-0 z-10 bg-surface px-4 py-2.5 group-hover/row:bg-surface-2/40">
                        <div className="font-mono text-xs text-fg">{p.key}</div>
                        <div className="text-2xs text-faint">{p.description}</div>
                      </td>
                      {roleList.map((r) => (
                        <td
                          key={r.id}
                          className={cn("border-l border-line/60 px-3 py-2.5 text-center", roleHas(r, p.key) && "bg-success/[0.06]")}
                        >
                          {roleHas(r, p.key) ? (
                            <span className="mx-auto inline-grid h-6 w-6 place-items-center rounded-md bg-success/12 text-success ring-1 ring-inset ring-success/25 transition-transform duration-150 group-hover/row:scale-110">
                              <IconCheck size={14} />
                            </span>
                          ) : (
                            <span className="mx-auto block h-1.5 w-1.5 rounded-full bg-faint/25" aria-label="not granted" />
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ---- Device access (resource-level entitlement) ------------------------------
   A role's `device:connect` permission says the role may connect to *something*;
   this editor says to *what*. Scope 'all' reaches every device in the org (the
   default); 'scoped' narrows reach to the union of the chosen device types and
   asset groups. A user's effective access is the union across their roles. */

// Only roles that can actually connect have anything to scope. Showing the
// editor on an auditor role would imply reach it doesn't have.
const roleConnects = (r: Role) => isSuperRole(r) || r.permissions.includes("device:connect");

function DeviceAccessEditor({
  role,
  onClose,
  onSaved,
}: {
  role: Role;
  onClose: () => void;
  onSaved: () => void;
}) {
  const access = useQuery<RoleDeviceAccess>({
    queryKey: ["role-device-access", role.id],
    queryFn: async () => (await api.get<RoleDeviceAccess>(`/roles/${role.id}/device-access`)).data,
    staleTime: 0,
  });
  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data,
  });

  const [scope, setScope] = useState<"all" | "scoped">("all");
  const [types, setTypes] = useState<Set<string>>(new Set());
  const [gids, setGids] = useState<Set<string>>(new Set());

  // Seed the form once the server state lands.
  useEffect(() => {
    if (!access.data) return;
    setScope(access.data.device_scope);
    setTypes(new Set(access.data.device_types));
    setGids(new Set(access.data.group_ids));
  }, [access.data]);

  const toggleIn = (set: Set<string>, put: (s: Set<string>) => void) => (v: string) => {
    const n = new Set(set);
    n.has(v) ? n.delete(v) : n.add(v);
    put(n);
  };

  const save = useMutation({
    mutationFn: async () =>
      api.put(`/roles/${role.id}/device-access`, {
        device_scope: scope,
        device_types: [...types],
        group_ids: [...gids],
      }),
    onSuccess: onSaved,
  });

  // A scoped role granting nothing reaches nothing. That's a legitimate
  // configuration, but it's worth saying out loud before it's saved.
  const denyAll = scope === "scoped" && types.size === 0 && gids.size === 0;
  // The device-type vocabulary plus any type a role was already granted that
  // isn't in it (device_type is free-form, so a scope may name anything).
  const typeOptions = [...new Set([...DEVICE_TYPES, ...types])];

  return (
    <Modal
      title={`Device access — ${role.name}`}
      icon={IconDevices}
      size="lg"
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={save.isPending || access.isLoading} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save device access"}
          </button>
        </>
      }
    >
      {save.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(save.error, "Could not update device access")} />
        </div>
      )}
      {access.isError && <ErrorNote message="Failed to load device access" />}
      {access.isLoading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted">
          <Spinner /> Loading device access…
        </div>
      )}
      {access.data && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <ScopeOption
              active={scope === "all"}
              onClick={() => setScope("all")}
              icon={IconGlobe}
              title="All devices"
              body="Every device in the organization, including ones added later."
            />
            <ScopeOption
              active={scope === "scoped"}
              onClick={() => setScope("scoped")}
              icon={IconLock}
              title="Scoped"
              body="Only the device types and asset groups selected below."
            />
          </div>

          {scope === "scoped" && (
            <>
              <Field label="Device types" hint="Any device of a selected type is in reach.">
                <div className="flex flex-wrap gap-1.5">
                  {typeOptions.map((t) => (
                    <ChipToggle key={t} on={types.has(t)} onClick={() => toggleIn(types, setTypes)(t)}>
                      {deviceTypeLabel(t)}
                    </ChipToggle>
                  ))}
                </div>
              </Field>

              <Field
                label="Asset groups"
                hint={
                  groups.data && groups.data.length === 0
                    ? "No asset groups exist yet. Create one on the Devices tab to scope by group."
                    : "Any device in a selected group is in reach."
                }
              >
                {groups.isLoading ? (
                  <Skeleton className="h-8" />
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {(groups.data ?? []).map((g) => (
                      <ChipToggle key={g.id} on={gids.has(g.id)} onClick={() => toggleIn(gids, setGids)(g.id)}>
                        <IconFolder size={13} /> {g.name}
                      </ChipToggle>
                    ))}
                  </div>
                )}
              </Field>

              {denyAll && (
                <div className="rounded-lg border border-warn/25 bg-warn/[0.07] px-3 py-2.5 text-xs text-warn">
                  This role reaches no devices. Anyone whose only role is <strong>{role.name}</strong> will be denied
                  every connection.
                </div>
              )}
            </>
          )}

          <p className="text-2xs text-faint">
            A person's access is the union of their roles. A single role granting all devices overrides any narrower
            scope they also hold.
          </p>
        </div>
      )}
    </Modal>
  );
}

// The scope switch reads as two mutually exclusive postures, not a checkbox —
// picking one is the decision, so each states its consequence.
function ScopeOption({
  active,
  onClick,
  icon: Icon,
  title,
  body,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof IconShield;
  title: string;
  body: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-xl border p-3 text-left transition",
        active ? "border-accent/40 bg-accent-soft/60 ring-1 ring-inset ring-accent/20" : "border-line bg-surface-2/40 hover:border-line-strong",
      )}
    >
      <div className="flex items-center gap-2">
        <span className={cn("grid h-6 w-6 place-items-center rounded-md", active ? "bg-accent/15 text-accent" : "bg-surface-3 text-faint")}>
          <Icon size={13} />
        </span>
        <span className={cn("text-sm font-medium", active ? "text-fg" : "text-muted")}>{title}</span>
      </div>
      <p className="mt-1.5 text-xs text-faint">{body}</p>
    </button>
  );
}

function ChipToggle({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition",
        on
          ? "border-accent/40 bg-accent-soft text-accent"
          : "border-line bg-surface-2/50 text-muted hover:border-line-strong hover:text-fg",
      )}
    >
      {on ? <IconCheck size={12} /> : <IconMinus size={12} className="opacity-40" />}
      {children}
    </button>
  );
}

function RoleSummaryCard({
  role,
  groups,
  total,
  onEditAccess,
  onEditRank,
}: {
  role: Role;
  groups: PermGroup[];
  total: number;
  onEditAccess?: () => void;
  onEditRank?: () => void;
}) {
  const superRole = isSuperRole(role);
  const id = roleIdentity(role);
  const touched = groups.filter(([, ps]) => superRole || ps.some((p) => role.permissions.includes(p.key)));
  const pct = superRole ? 100 : total ? Math.round((role.permissions.length / total) * 100) : 0;
  return (
    <div className="group relative flex flex-col overflow-hidden rounded-xl card-grad p-4 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:shadow-md">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span
            className={cn(
              "grid h-9 w-9 shrink-0 place-items-center rounded-xl ring-1 ring-inset transition-shadow group-hover:shadow-glow-sm",
              TONE_TILE[id.tone],
            )}
          >
            <id.icon size={17} />
          </span>
          <div className="min-w-0">
            <div className="truncate font-medium text-fg">{role.name}</div>
            <div className="text-2xs uppercase tracking-wider text-faint">
              {superRole ? "full access" : `${role.permissions.length} of ${total} permissions`}
            </div>
          </div>
        </div>
        {role.is_system && <Badge tone="neutral">system</Badge>}
      </div>

      {/* Device reach — the resource-level half of what this role can do. */}
      {roleConnects(role) && (
        <div className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-line bg-surface-2/40 px-2.5 py-2">
          <div className="flex min-w-0 items-center gap-2">
            <IconDevices size={14} className="shrink-0 text-faint" />
            <span className="truncate text-xs text-muted">
              {superRole || role.device_scope !== "scoped" ? "Reaches all devices" : "Scoped device access"}
            </span>
          </div>
          {onEditAccess && !superRole && (
            <button className="shrink-0 text-2xs font-medium text-accent transition hover:underline" onClick={onEditAccess}>
              Edit
            </button>
          )}
        </div>
      )}

      {/* Approval rank — who this role can sign off for. Shown next to device
          reach because both answer "how far does this role go". */}
      <div className="mt-2 flex items-center justify-between gap-2 rounded-lg border border-line bg-surface-2/40 px-2.5 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <IconShield size={14} className="shrink-0 text-faint" />
          <span className="truncate text-xs text-muted">
            {superRole
              ? "Approves anybody"
              : role.approval_level > 0
                ? `Approval rank ${role.approval_level}`
                : "Cannot approve anybody"}
          </span>
        </div>
        {onEditRank && !superRole && (
          <button className="shrink-0 text-2xs font-medium text-accent transition hover:underline" onClick={onEditRank}>
            Edit
          </button>
        )}
      </div>

      {/* Grant-coverage bar */}
      <div className="mt-3">
        <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
          <div
            className={cn("h-full rounded-full transition-[width] duration-500", superRole ? "accent-grad" : "bg-accent")}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {role.description && <p className="mt-3 text-xs text-muted">{role.description}</p>}
      <div className="mt-3 flex flex-wrap gap-1.5">
        {superRole ? (
          <Badge tone="accent" dot>
            Full access
          </Badge>
        ) : touched.length ? (
          touched.map(([res]) => (
            <Badge key={res} tone="neutral">
              {resourceLabel(res)}
            </Badge>
          ))
        ) : (
          <span className="text-xs text-faint">no permissions</span>
        )}
      </div>
    </div>
  );
}

function RoleChecklist({
  roles,
  selected,
  toggle,
}: {
  roles: Role[];
  selected: Set<string>;
  toggle: (id: string) => void;
}) {
  return (
    <div className="space-y-2">
      {roles.map((r) => (
        <label key={r.id} className="flex items-center gap-2 text-sm text-fg">
          <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggle(r.id)} />
          <span className="font-medium">{r.name}</span>
          <span className="text-xs text-faint">{r.description}</span>
        </label>
      ))}
    </div>
  );
}

function CreateUserModal({
  roles,
  onClose,
  onCreated,
}: {
  roles: Role[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  const create = useMutation({
    mutationFn: async () =>
      api.post("/users", { email, username, password, role_ids: [...sel] }),
    onSuccess: onCreated,
  });

  return (
    <Modal
      title="Add user"
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={create.isPending || !email || !scorePassword(password).acceptable}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Creating…" : "Create user"}
          </button>
        </>
      }
    >
      {create.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(create.error, "Could not create user")} />
        </div>
      )}
      <Field label="Email">
        <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@example.com" />
      </Field>
      <Field label="Username">
        <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="optional" />
      </Field>
      <Field label="Temporary password" hint="They'll be asked to replace this the first time they sign in.">
        <input
          className="input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
      </Field>
      <PasswordStrength value={password} />
      <Field label="Roles">
        <RoleChecklist roles={roles} selected={sel} toggle={toggle} />
      </Field>
    </Modal>
  );
}

function EditRolesModal({
  user,
  roles,
  onClose,
  onSaved,
}: {
  user: UserRow;
  roles: Role[];
  onClose: () => void;
  onSaved: () => void;
}) {
  // Map the user's current role names back to ids using the roles catalogue.
  const initial = new Set(roles.filter((r) => user.roles.includes(r.name)).map((r) => r.id));
  const [sel, setSel] = useState<Set<string>>(initial);
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  const save = useMutation({
    mutationFn: async () => api.put(`/users/${user.user_id}/roles`, { role_ids: [...sel] }),
    onSuccess: onSaved,
  });

  // What this change actually does to their standing. Roles are a checklist, but
  // the thing an administrator is really deciding is how far this person can
  // reach and whose access they can sign off — so spell that out rather than
  // leaving it to be inferred from a set of ticks.
  const selected = roles.filter((r) => sel.has(r.id));
  const beforeRank = user.approval_level ?? 0;
  const afterRank = selected.reduce((m, r) => Math.max(m, r.approval_level ?? 0), 0);
  const becomesSuper = selected.some(isSuperRole);
  const wasSuper = user.is_super_admin;
  const rankMoved = afterRank !== beforeRank;

  return (
    <Modal
      title={`Roles — ${user.email}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save roles"}
          </button>
        </>
      }
    >
      {save.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(save.error, "Could not update roles")} />
        </div>
      )}
      <RoleChecklist roles={roles} selected={sel} toggle={toggle} />

      <div className="mt-4 space-y-2 border-t border-line pt-3 text-sm">
        {rankMoved && (
          <div className={cn("flex items-center gap-2", afterRank > beforeRank ? "text-warn" : "text-fg")}>
            <IconShield size={14} className="shrink-0" />
            <span>
              Approval rank {afterRank > beforeRank ? "rises" : "falls"} from{" "}
              <b>{beforeRank}</b> to <b>{afterRank}</b> — they will be able to decide requests from
              anybody ranked below {afterRank}.
            </span>
          </div>
        )}
        {becomesSuper && !wasSuper && (
          <div className="flex items-center gap-2 text-warn">
            <IconAlert size={14} className="shrink-0" />
            <span>
              <b>Super Admin</b> is unrestricted and crosses every organization. It is not a higher
              rank — it is no limit at all.
            </span>
          </div>
        )}
        {wasSuper && !becomesSuper && (
          <div className="flex items-center gap-2 text-warn">
            <IconAlert size={14} className="shrink-0" />
            <span>
              This removes <b>Super Admin</b>. Make sure somebody else still holds it.
            </span>
          </div>
        )}
        {selected.length === 0 && (
          <div className="flex items-center gap-2 text-danger">
            <IconAlert size={14} className="shrink-0" />
            <span>No roles selected — they will be able to sign in and do nothing.</span>
          </div>
        )}
        <p className="text-xs text-muted">
          Saving signs this person out of the console, so the change takes effect on their next
          sign-in rather than whenever their token happens to expire.
        </p>
      </div>
    </Modal>
  );
}

// ApprovalRankEditor sets a role's rank in the approval hierarchy.
//
// The one dial that decides who can sign off whose access. It is presented as a
// ladder rather than a number box, because "50" means nothing on its own and
// "above Operator, below Organization Admin" means everything.
function ApprovalRankEditor({
  role,
  onClose,
  onSaved,
}: {
  role: Role;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [level, setLevel] = useState(role.approval_level);

  const roles = useQuery<Role[]>({
    queryKey: ["roles"],
    queryFn: async () => (await api.get<{ data: Role[] }>("/roles")).data.data,
  });

  const save = useMutation({
    mutationFn: async () => api.put(`/roles/${role.id}/approval-level`, { approval_level: level }),
    onSuccess: onSaved,
    onError: (e) => toast.error(problemDetail(e, "Could not set the approval rank")),
  });

  // Who this rank would be able to decide for, and who could decide for them.
  const others = (roles.data ?? []).filter((r) => r.id !== role.id);
  const canApprove = others.filter((r) => r.approval_level < level);
  const approvedBy = others.filter((r) => r.approval_level > level);

  return (
    <Modal onClose={onClose} title={`Approval rank — ${role.name}`} icon={IconShield}>
      <div className="space-y-4">
        <p className="text-sm text-muted">
          An approver must outrank the requester <b>strictly</b>. That is also why nobody can approve
          their own request, and why two people at the same rank cannot sign off each other&rsquo;s.
        </p>

        <Field label="Rank" hint="0–999. Gaps are deliberate: leave room to slot a role in later.">
          <Input
            type="number"
            min={0}
            max={999}
            value={level}
            onChange={(e) => setLevel(Math.max(0, Math.min(999, Number(e.target.value))))}
          />
        </Field>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-line bg-surface-2 p-3">
            <div className="text-2xs font-semibold uppercase tracking-wider text-faint">Can approve</div>
            {canApprove.length === 0 ? (
              <p className="mt-1 text-xs text-warn">Nobody. This role cannot decide any request.</p>
            ) : (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {canApprove.map((r) => (
                  <Badge key={r.id} tone="neutral">{r.name}</Badge>
                ))}
              </div>
            )}
          </div>
          <div className="rounded-lg border border-line bg-surface-2 p-3">
            <div className="text-2xs font-semibold uppercase tracking-wider text-faint">Approved by</div>
            {approvedBy.length === 0 ? (
              <p className="mt-1 text-xs text-warn">
                Nobody outranks this. Requests from it can only expire.
              </p>
            ) : (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {approvedBy.map((r) => (
                  <Badge key={r.id} tone="neutral">{r.name}</Badge>
                ))}
              </div>
            )}
          </div>
        </div>

        <p className="text-xs text-muted">
          Deciding also needs the <span className="font-mono">approval:decide</span> permission. Rank
          says <em>who</em> they may decide for; the permission says <em>whether</em> they may decide at all.
        </p>

        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>Save</Button>
        </div>
      </div>
    </Modal>
  );
}

// ResetPasswordModal issues a temporary password for somebody who is locked out.
//
// The value is shown ONCE and never retrievable again, so the reveal stays until
// it is dismissed — no auto-hide, no toast. An administrator who looks away and
// comes back to an empty screen has to reset the account a second time, which
// signs the person out again.
function ResetPasswordModal({ user, onClose }: { user: UserRow; onClose: () => void }) {
  const [issued, setIssued] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const reset = useMutation({
    mutationFn: async () =>
      (await api.post<{ password: string }>(`/users/${user.user_id}/reset-password`, {})).data,
    onSuccess: (d) => setIssued(d.password),
    onError: (e) => toast.error(problemDetail(e, "Could not reset the password")),
  });

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(issued ?? "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      toast.error("Couldn't reach the clipboard — select the text and copy it");
    }
  };

  if (issued) {
    return (
      <Modal
        title="Temporary password"
        onClose={onClose}
        footer={
          <button className="btn-primary" onClick={onClose}>
            I have given it to them
          </button>
        }
      >
        <p className="text-sm text-fg">
          Give this to <b>{user.email}</b> over a channel you trust. It is shown once and cannot be
          retrieved again.
        </p>
        <div className="mt-3 rounded-lg border border-accent/40 bg-accent-soft/40 p-3">
          <div className="flex items-center justify-between gap-3">
            <code className="break-all font-mono text-base text-fg">{issued}</code>
            <button className="btn-subtle shrink-0" onClick={copy}>
              {copied ? <IconCheck size={15} /> : <IconClipboard size={15} />}
            </button>
          </div>
        </div>
        <ul className="mt-3 space-y-1 text-xs text-muted">
          <li>They must choose a new password at their next sign-in.</li>
          <li>Every session they had is signed out, so a lost laptop stops being a way in.</li>
        </ul>
      </Modal>
    );
  }

  return (
    <Modal
      title={`Reset password — ${user.email}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={reset.isPending} onClick={() => reset.mutate()}>
            {reset.isPending ? "Resetting…" : "Issue temporary password"}
          </button>
        </>
      }
    >
      <p className="text-sm text-fg">
        Use this when somebody has forgotten their password and cannot sign in.
      </p>
      <ul className="mt-3 space-y-1.5 text-sm text-muted">
        <li>A random temporary password is generated and shown to you once.</li>
        <li>They are forced to replace it at next sign-in, so you never hold their credential.</li>
        <li>Every session they currently have is signed out.</li>
      </ul>
      {/* Say why there is no "set it to the usual one" box. */}
      <p className="mt-3 text-xs text-muted">
        There is deliberately no fixed default. On a platform that brokers privileged access, a
        well-known reset password would make every account mid-reset takeable by anyone who had read
        the documentation.
      </p>
    </Modal>
  );
}
