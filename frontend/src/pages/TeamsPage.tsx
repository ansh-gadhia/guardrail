import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { AssetGroup, Team, TeamGrants, TeamMember, UserRow, AccessLevel } from "@/lib/types";
import { ACCESS_LEVELS } from "@/lib/types";
import { useAuth } from "@/store/auth";
import {
  Badge, Button, EmptyState, ErrorNote, Field, Hairline, Input, Modal, PageHero,
  Panel, Select, Skeleton, Spinner, Textarea, cn,
} from "@/components/ui";
import {
  IconAlert, IconCheck, IconDevices, IconFolder, IconGlobe, IconPlus, IconTrash, IconUsers,
} from "@/components/icons";
import { toast } from "@/components/Toast";
import { DEVICE_TYPES, deviceTypeLabel } from "./DevicesPage";

// Teams — the second axis of device authorization.
//
// A role answers "what may this person do"; a team answers "which devices may
// they do it to". Keeping them apart is what stops the role list growing as
// roles × teams (IT Operator, IT Auditor, Security Operator, Security Auditor,
// and another pair every time either axis grows).
//
// The page is deliberately built around the two questions in that order: who is
// in the team, and what does the team reach. Everything else is detail.

const LEVEL_TONE: Record<string, "neutral" | "info" | "warn" | "success"> = {
  view: "neutral",
  connect: "info",
  manage: "warn",
};

function LevelBadge({ level }: { level: AccessLevel }) {
  if (level === "none") return <span className="text-xs text-muted">—</span>;
  return <Badge tone={LEVEL_TONE[level] ?? "neutral"}>{level}</Badge>;
}

export function TeamsPage() {
  const qc = useQueryClient();
  const canWrite = useAuth((s) => s.has("team:write"));
  const [editing, setEditing] = useState<Team | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<Team | null>(null);

  const teams = useQuery<Team[]>({
    queryKey: ["teams"],
    queryFn: async () => (await api.get<{ data: Team[] }>("/teams")).data.data ?? [],
  });

  const remove = useMutation({
    mutationFn: async (id: string) => api.delete(`/teams/${id}`),
    onSuccess: () => {
      toast.success("Team deleted — the reach it granted is gone with it");
      setSelected(null);
      void qc.invalidateQueries({ queryKey: ["teams"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not delete the team")),
  });

  const rows = teams.data ?? [];

  return (
    <div className="space-y-5">
      <PageHero
        icon={IconUsers}
        title="Teams"
        subtitle="Which devices each team reaches. A role decides what a person may do; a team decides what they may do it to."
        actions={
          canWrite ? (
            <Button variant="primary" onClick={() => setShowCreate(true)}>
              <IconPlus size={16} /> New team
            </Button>
          ) : null
        }
      />

      {teams.isError && <ErrorNote message={problemDetail(teams.error, "Could not load teams")} />}

      <Panel title="Teams" subtitle={`${rows.length} in this organization`}>
        {teams.isLoading ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={IconUsers}
            title="No teams yet"
            message="Without a team, device reach comes from roles alone. Create a team to give a group of people access to a set of devices without inventing a role per department."
          />
        ) : (
          <div className="divide-y divide-hairline">
            {rows.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setSelected(t)}
                className={cn(
                  "flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-subtle",
                  selected?.id === t.id && "bg-subtle",
                )}
              >
                <IconUsers size={16} className="shrink-0 text-muted" />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{t.name}</div>
                  {t.description && <div className="truncate text-xs text-muted">{t.description}</div>}
                </div>
                <span className="text-xs text-muted">
                  {t.member_count} {t.member_count === 1 ? "member" : "members"}
                </span>
                {t.all_devices_level !== "none" && (
                  <Badge tone="warn">
                    <IconGlobe size={12} /> all devices · {t.all_devices_level}
                  </Badge>
                )}
              </button>
            ))}
          </div>
        )}
      </Panel>

      {selected && (
        <TeamDetail
          team={selected}
          canWrite={canWrite}
          onEdit={() => setEditing(selected)}
          onDelete={() => {
            if (window.confirm(`Delete "${selected.name}"? Everyone in it loses the reach it granted.`)) {
              remove.mutate(selected.id);
            }
          }}
        />
      )}

      {(showCreate || editing) && (
        <TeamForm
          team={editing}
          onClose={() => {
            setShowCreate(false);
            setEditing(null);
          }}
          onSaved={(t) => {
            setSelected(t);
            setShowCreate(false);
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

// ---- one team -------------------------------------------------------------

function TeamDetail({
  team, canWrite, onEdit, onDelete,
}: {
  team: Team;
  canWrite: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Panel
        title={team.name}
        subtitle={team.description || "No description"}
        actions={
          canWrite ? (
            <div className="flex gap-2">
              <Button variant="ghost" onClick={onEdit}>Edit</Button>
              <Button variant="danger" onClick={onDelete}>
                <IconTrash size={15} /> Delete
              </Button>
            </div>
          ) : null
        }
      >
        <Members team={team} canWrite={canWrite} />
      </Panel>
      <Panel title="Device reach" subtitle="What this team can get to">
        <Grants team={team} canWrite={canWrite} />
      </Panel>
    </div>
  );
}

function Members({ team, canWrite }: { team: Team; canWrite: boolean }) {
  const qc = useQueryClient();
  const [adding, setAdding] = useState("");

  const members = useQuery<TeamMember[]>({
    queryKey: ["team-members", team.id],
    queryFn: async () => (await api.get<{ data: TeamMember[] }>(`/teams/${team.id}/members`)).data.data ?? [],
  });
  const people = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data ?? [],
  });

  const save = useMutation({
    mutationFn: async (ids: string[]) => api.put(`/teams/${team.id}/members`, { user_ids: ids }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["team-members", team.id] });
      void qc.invalidateQueries({ queryKey: ["teams"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not update membership")),
  });

  const current = members.data ?? [];
  const currentIDs = current.map((m) => m.user_id);
  const inTeam = new Set(currentIDs);
  const available = (people.data ?? []).filter((p) => !inTeam.has(p.user_id));

  if (members.isLoading) return <div className="p-4"><Skeleton className="h-16" /></div>;

  return (
    <div className="space-y-3">
      {current.length === 0 ? (
        <p className="text-sm text-muted">
          Nobody is in this team yet, so its grants reach nobody.
        </p>
      ) : (
        <ul className="divide-y divide-hairline">
          {current.map((m) => (
            <li key={m.user_id} className="flex items-center gap-2 py-2">
              <span className="min-w-0 flex-1 truncate text-sm">{m.email}</span>
              {m.status !== "active" && <Badge tone="neutral">{m.status}</Badge>}
              {canWrite && (
                <button
                  type="button"
                  aria-label={`Remove ${m.email}`}
                  className="text-muted transition hover:text-danger"
                  onClick={() => save.mutate(currentIDs.filter((id) => id !== m.user_id))}
                >
                  <IconTrash size={15} />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canWrite && (
        <>
          <Hairline />
          <div className="flex gap-2">
            <Select value={adding} onChange={(e) => setAdding(e.target.value)} className="flex-1">
              <option value="">Add someone…</option>
              {available.map((p) => (
                <option key={p.user_id} value={p.user_id}>{p.email}</option>
              ))}
            </Select>
            <Button
              disabled={!adding || save.isPending}
              onClick={() => {
                save.mutate([...currentIDs, adding]);
                setAdding("");
              }}
            >
              {save.isPending ? <Spinner /> : <IconPlus size={16} />} Add
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function Grants({ team, canWrite }: { team: Team; canWrite: boolean }) {
  const qc = useQueryClient();
  const [pendingGroup, setPendingGroup] = useState("");
  const [pendingGroupLevel, setPendingGroupLevel] = useState<string>("connect");
  const [pendingType, setPendingType] = useState("");
  const [pendingTypeLevel, setPendingTypeLevel] = useState<string>("connect");

  const grants = useQuery<TeamGrants>({
    queryKey: ["team-grants", team.id],
    queryFn: async () => (await api.get<TeamGrants>(`/teams/${team.id}/grants`)).data,
  });
  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data ?? [],
  });

  const save = useMutation({
    mutationFn: async (next: TeamGrants) => api.put(`/teams/${team.id}/grants`, next),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["team-grants", team.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not update grants")),
  });

  const g = grants.data ?? { groups: [], device_types: [] };
  const granted = new Set(g.groups.map((x) => x.asset_group_id));
  const availableGroups = (groups.data ?? []).filter((x) => !granted.has(x.id));
  const grantedTypes = new Set(g.device_types.map((x) => x.device_type.toLowerCase()));

  if (grants.isLoading) return <div className="p-4"><Skeleton className="h-16" /></div>;

  const blanket = team.all_devices_level !== "none";

  return (
    <div className="space-y-4">
      {blanket && (
        <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn/10 p-3 text-sm">
          <IconGlobe size={16} className="mt-0.5 shrink-0" />
          <span>
            This team reaches <strong>every device</strong> in the organization at{" "}
            <strong>{team.all_devices_level}</strong>, including devices registered later.
            The grants below add nothing on top of that.
          </span>
        </div>
      )}

      <section className="space-y-2">
        <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          <IconFolder size={13} /> Asset groups
        </h4>
        {g.groups.length === 0 ? (
          <p className="text-sm text-muted">No group grants.</p>
        ) : (
          <ul className="divide-y divide-hairline">
            {g.groups.map((row) => (
              <li key={row.asset_group_id} className="flex items-center gap-2 py-2">
                <span className="min-w-0 flex-1 truncate text-sm">{row.name}</span>
                {canWrite ? (
                  <Select
                    value={row.level}
                    className="w-32"
                    onChange={(e) =>
                      save.mutate({
                        ...g,
                        groups: g.groups.map((x) =>
                          x.asset_group_id === row.asset_group_id
                            ? { ...x, level: e.target.value as TeamGrants["groups"][number]["level"] }
                            : x,
                        ),
                      })
                    }
                  >
                    {ACCESS_LEVELS.map((l) => (
                      <option key={l.value} value={l.value}>{l.label}</option>
                    ))}
                  </Select>
                ) : (
                  <LevelBadge level={row.level} />
                )}
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`Revoke ${row.name}`}
                    className="text-muted transition hover:text-danger"
                    onClick={() =>
                      save.mutate({ ...g, groups: g.groups.filter((x) => x.asset_group_id !== row.asset_group_id) })
                    }
                  >
                    <IconTrash size={15} />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {canWrite && (
          <div className="flex gap-2">
            <Select value={pendingGroup} onChange={(e) => setPendingGroup(e.target.value)} className="flex-1">
              <option value="">Grant a group…</option>
              {availableGroups.map((x) => (
                <option key={x.id} value={x.id}>{x.name}</option>
              ))}
            </Select>
            <Select value={pendingGroupLevel} onChange={(e) => setPendingGroupLevel(e.target.value)} className="w-32">
              {ACCESS_LEVELS.map((l) => (
                <option key={l.value} value={l.value}>{l.label}</option>
              ))}
            </Select>
            <Button
              disabled={!pendingGroup || save.isPending}
              onClick={() => {
                const name = availableGroups.find((x) => x.id === pendingGroup)?.name ?? "";
                save.mutate({
                  ...g,
                  groups: [
                    ...g.groups,
                    { asset_group_id: pendingGroup, name, level: pendingGroupLevel as "view" | "connect" | "manage" },
                  ],
                });
                setPendingGroup("");
              }}
            >
              <IconPlus size={16} />
            </Button>
          </div>
        )}
        <p className="text-xs text-muted">
          A group grant covers the groups nested inside it, so a tree can be reorganised without silently revoking access.
        </p>
      </section>

      <Hairline />

      <section className="space-y-2">
        <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          <IconDevices size={13} /> Device types
        </h4>
        {g.device_types.length === 0 ? (
          <p className="text-sm text-muted">No device-type grants.</p>
        ) : (
          <ul className="divide-y divide-hairline">
            {g.device_types.map((row) => (
              <li key={row.device_type} className="flex items-center gap-2 py-2">
                <span className="min-w-0 flex-1 truncate text-sm">{deviceTypeLabel(row.device_type)}</span>
                <LevelBadge level={row.level} />
                {canWrite && (
                  <button
                    type="button"
                    aria-label={`Revoke ${row.device_type}`}
                    className="text-muted transition hover:text-danger"
                    onClick={() =>
                      save.mutate({ ...g, device_types: g.device_types.filter((x) => x.device_type !== row.device_type) })
                    }
                  >
                    <IconTrash size={15} />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {canWrite && (
          <div className="flex gap-2">
            <Select value={pendingType} onChange={(e) => setPendingType(e.target.value)} className="flex-1">
              <option value="">Grant a device type…</option>
              {DEVICE_TYPES.filter((t) => !grantedTypes.has(t.toLowerCase())).map((t) => (
                <option key={t} value={t}>{deviceTypeLabel(t)}</option>
              ))}
            </Select>
            <Select value={pendingTypeLevel} onChange={(e) => setPendingTypeLevel(e.target.value)} className="w-32">
              {ACCESS_LEVELS.map((l) => (
                <option key={l.value} value={l.value}>{l.label}</option>
              ))}
            </Select>
            <Button
              disabled={!pendingType || save.isPending}
              onClick={() => {
                save.mutate({
                  ...g,
                  device_types: [
                    ...g.device_types,
                    { device_type: pendingType, level: pendingTypeLevel as "view" | "connect" | "manage" },
                  ],
                });
                setPendingType("");
              }}
            >
              <IconPlus size={16} />
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}

// ---- create / edit --------------------------------------------------------

function TeamForm({
  team, onClose, onSaved,
}: {
  team: Team | null;
  onClose: () => void;
  onSaved: (t: Team) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(team?.name ?? "");
  const [description, setDescription] = useState(team?.description ?? "");
  const [blanket, setBlanket] = useState<string>(team?.all_devices_level ?? "none");

  const save = useMutation({
    mutationFn: async () => {
      const body = { name, description, all_devices_level: blanket };
      const res = team
        ? await api.put<Team>(`/teams/${team.id}`, body)
        : await api.post<Team>("/teams", body);
      return res.data;
    },
    onSuccess: (t) => {
      toast.success(team ? "Team updated" : "Team created");
      void qc.invalidateQueries({ queryKey: ["teams"] });
      onSaved(t);
    },
    onError: (e) => toast.error(problemDetail(e, "Could not save the team")),
  });

  const blanketHint = useMemo(() => {
    if (blanket === "none") return "This team reaches only what its grants name.";
    return `Everyone in this team reaches EVERY device at "${blanket}" — including devices registered later.`;
  }, [blanket]);

  return (
    <Modal onClose={onClose} title={team ? "Edit team" : "New team"} icon={IconUsers}>
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="IT" autoFocus />
        </Field>
        <Field label="Description" hint="What this team is for.">
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
        </Field>
        <Field
          label="Blanket grant"
          hint={
            <span className={cn(blanket !== "none" && "text-warn")}>
              {blanket !== "none" && <IconAlert size={12} className="mr-1 inline" />}
              {blanketHint}
            </span>
          }
        >
          <Select value={blanket} onChange={(e) => setBlanket(e.target.value)}>
            <option value="none">None — grants below only</option>
            {ACCESS_LEVELS.map((l) => (
              <option key={l.value} value={l.value}>Every device · {l.label}</option>
            ))}
          </Select>
        </Field>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? <Spinner /> : <IconCheck size={16} />} Save
          </Button>
        </div>
      </div>
    </Modal>
  );
}
