import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Account, CredentialMode, Device, Role, WhoAmI } from "@/lib/types";
import { defaultInjectionFor, injectionMethodsFor } from "@/lib/types";
import { useAuth } from "@/store/auth";
import {
  Badge, Button, ErrorNote, Field, Hairline, Input, Modal, Select, Spinner, Switch,
} from "@/components/ui";
import { IconAlert, IconCheck, IconKey, IconTrash, IconUsers } from "@/components/icons";
import { toast } from "@/components/Toast";

// Who this device authenticates as, and who has to say yes before you reach it.
//
// Both settings are policy about the device rather than facts about it, so they
// live together and away from the address and the tags.

export function DeviceAccessPolicy({
  device,
  canEdit,
  toBody,
}: {
  device: Device;
  canEdit: boolean;
  toBody: (d: Device) => Record<string, unknown>;
}) {
  const qc = useQueryClient();
  const canBind = useAuth((s) => s.has("credential:write"));
  const [manageAccounts, setManageAccounts] = useState(false);

  const patch = useMutation({
    mutationFn: async (body: Record<string, unknown>) =>
      api.patch(`/devices/${device.id}`, { ...toBody(device), ...body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["device", device.id] });
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not save the policy")),
  });

  const perUser = device.credential_mode === "per_user";

  return (
    <div className="space-y-5">
      <WhoAmIBanner device={device} />

      <Field
        label="Credentials"
        hint={
          perUser
            ? "Each person connects as their own named account on the device, so the device's own logs record who was actually there. Somebody with no account bound here cannot connect."
            : "Everyone entitled to this device is injected with the same vaulted login."
        }
      >
        <Select
          value={device.credential_mode}
          disabled={!canEdit || patch.isPending}
          onChange={(e) => {
            const mode = e.target.value as CredentialMode;
            patch.mutate(
              { credential_mode: mode },
              {
                onSuccess: () =>
                  toast.success(
                    mode === "per_user"
                      ? "Each person now connects as their own account"
                      : "Everyone now connects as the device's shared login",
                  ),
              },
            );
          }}
        >
          <option value="shared">Shared login — one credential for everyone</option>
          <option value="per_user">Per-user accounts — each person has their own</option>
        </Select>
      </Field>

      {perUser && (
        <div className="rounded-lg border border-line bg-surface-2 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm">
              <div className="font-medium text-fg">Per-user accounts</div>
              <p className="mt-0.5 text-xs text-muted">
                Named logins that exist <b>on this device</b> — never somebody's own password.
              </p>
            </div>
            {canBind && (
              <Button size="sm" variant="subtle" onClick={() => setManageAccounts(true)}>
                <IconUsers size={14} /> Manage
              </Button>
            )}
          </div>
          <AccountSummary device={device} />
        </div>
      )}

      <Hairline />

      <Field
        label="Approval"
        hint="When on, connecting waits for a decision from somebody who ranks above the requester. Nobody can approve their own request."
      >
        <Switch
          checked={device.requires_approval}
          disabled={!canEdit || patch.isPending}
          onChange={(v) =>
            patch.mutate(
              { requires_approval: v },
              {
                onSuccess: () =>
                  toast.success(v ? "Connecting now needs approval" : "Approval turned off for this device"),
              },
            )
          }
          label="Require approval to connect"
        />
      </Field>

      {device.requires_approval && (
        <>
          <Field
            label="Approvals needed"
            hint="Two is the two-person rule: right for a core firewall, overkill for a lab switch. A single denial still settles it either way."
          >
            <Select
              value={device.min_approvals}
              disabled={!canEdit || patch.isPending}
              onChange={(e) =>
                patch.mutate(
                  { min_approvals: Number(e.target.value) },
                  { onSuccess: () => toast.success("Approval threshold saved") },
                )
              }
            >
              {[1, 2, 3].map((n) => (
                <option key={n} value={n}>
                  {n === 1 ? "One approval" : `${n} approvals, from different people`}
                </option>
              ))}
            </Select>
          </Field>
          <ApprovalCoverageWarning />
        </>
      )}

      {manageAccounts && (
        <AccountsModal device={device} onClose={() => setManageAccounts(false)} />
      )}
    </div>
  );
}

// WhoAmIBanner answers "which account am I about to be" before the click.
//
// It removes a whole class of confusion — and on a per-user device with nothing
// bound for you it says so HERE, rather than letting you find out from a refused
// connect.
function WhoAmIBanner({ device }: { device: Device }) {
  const q = useQuery({
    queryKey: ["device-whoami", device.id],
    queryFn: async () => (await api.get<WhoAmI>(`/devices/${device.id}/whoami`)).data,
  });

  if (q.isLoading || !q.data) return null;
  const w = q.data;

  if (!w.has_credential) {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-warn/40 bg-warn/5 p-3 text-sm">
        <IconAlert size={16} className="mt-0.5 shrink-0 text-warn" />
        <div>
          <div className="font-medium text-fg">
            {w.credential_mode === "per_user"
              ? "You have no account on this device"
              : "This device has no credential"}
          </div>
          <p className="mt-0.5 text-muted">
            {w.credential_mode === "per_user"
              ? "Connecting will be refused until somebody binds an account for you. It will not fall back to the shared login — that would put you in the device's logs as somebody else."
              : w.allow_unmanaged
                ? "Break-glass is on, so you can connect and log in by hand."
                : "Bind a credential before anybody can connect."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-2 rounded-lg border border-line bg-surface-2 p-3 text-sm">
      <IconKey size={16} className="mt-0.5 shrink-0 text-accent" />
      <div className="min-w-0">
        <div className="text-fg">
          You will connect as <span className="font-mono font-medium">{w.username || "(no username)"}</span>
        </div>
        <p className="mt-0.5 text-xs text-muted">
          {w.per_user ? "Your own account" : "The device's shared login"}
          {w.inherited && " · inherited from an asset group"}
          {typeof w.age_days === "number" && w.age_days > 180 && (
            <span className="text-warn"> · secret unchanged for {w.age_days} days</span>
          )}
        </p>
      </div>
    </div>
  );
}

function AccountSummary({ device }: { device: Device }) {
  const q = useQuery({
    queryKey: ["device-accounts", device.id],
    queryFn: async () =>
      (await api.get<{ accounts: Account[]; inherited: Account[] }>(`/devices/${device.id}/accounts`)).data,
  });
  if (q.isLoading || !q.data) return null;
  const own = q.data.accounts ?? [];
  const inherited = q.data.inherited ?? [];
  if (own.length === 0 && inherited.length === 0) {
    return (
      <p className="mt-2 text-xs text-warn">
        No accounts bound. Nobody can connect to this device until one exists for them.
      </p>
    );
  }
  return (
    <p className="mt-2 text-xs text-muted">
      {own.length} bound here
      {inherited.length > 0 && `, ${inherited.length} inherited from asset groups`}
    </p>
  );
}

// ApprovalCoverageWarning refuses to let a device be gated silently into a
// deadlock: if nobody outranks a rank somebody actually holds, their requests
// can only ever expire — and they would find that out at 3am.
function ApprovalCoverageWarning() {
  const has = useAuth((s) => s.has);
  const q = useQuery({
    queryKey: ["approval-coverage"],
    queryFn: async () =>
      (await api.get<{ coverage: { level: number; approvers: number }[]; gaps: number }>("/approval-coverage")).data,
    enabled: has("role:read"),
  });
  if (!q.data || q.data.gaps === 0) return null;
  const stranded = q.data.coverage.filter((c) => c.approvers === 0).map((c) => c.level);
  return (
    <div className="flex items-start gap-2 rounded-lg border border-warn/40 bg-warn/5 p-3 text-sm">
      <IconAlert size={16} className="mt-0.5 shrink-0 text-warn" />
      <div>
        <div className="font-medium text-fg">Some people cannot be approved</div>
        <p className="mt-0.5 text-muted">
          Nobody who holds <span className="font-mono">approval:decide</span> outranks{" "}
          {stranded.length === 1 ? "rank" : "ranks"} {stranded.join(", ")}. Requests from anybody at{" "}
          {stranded.length === 1 ? "that rank" : "those ranks"} can only expire. Raise somebody's approval
          level under <b>Access Control → Roles</b>.
        </p>
      </div>
    </div>
  );
}

// ---- account management ---------------------------------------------------

function AccountsModal({ device, onClose }: { device: Device; onClose: () => void }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<{ userID: string; username: string; injection: string } | null>(null);

  const accounts = useQuery({
    queryKey: ["device-accounts", device.id],
    queryFn: async () =>
      (await api.get<{ accounts: Account[]; inherited: Account[] }>(`/devices/${device.id}/accounts`)).data,
  });

  const people = useQuery({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: { user_id: string; email: string }[] }>("/users")).data.data ?? [],
  });

  const remove = useMutation({
    mutationFn: async (userID: string) => api.delete(`/devices/${device.id}/accounts/${userID}`),
    onSuccess: () => {
      toast.success("Account removed");
      void qc.invalidateQueries({ queryKey: ["device-accounts", device.id] });
      void qc.invalidateQueries({ queryKey: ["device-whoami", device.id] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not remove the account")),
  });

  const own = accounts.data?.accounts ?? [];
  const inherited = accounts.data?.inherited ?? [];
  const boundIDs = new Set(own.map((a) => a.user_id));
  const unbound = (people.data ?? []).filter((p) => !boundIDs.has(p.user_id));

  return (
    <Modal onClose={onClose} title={`Accounts on ${device.name}`} icon={IconUsers} size="lg">
      <div className="space-y-5">
        <p className="text-sm text-muted">
          Each person connects as their own named account on the device — <span className="font-mono">jsmith-admin</span>,
          not their GuardRail password. GuardRail never holds somebody's own login.
        </p>

        {accounts.isLoading ? (
          <Spinner />
        ) : accounts.error ? (
          <ErrorNote message={problemDetail(accounts.error, "Could not load accounts")} />
        ) : (
          <>
            <div>
              <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">Bound to this device</h4>
              {own.length === 0 ? (
                <p className="mt-2 text-sm text-muted">Nobody yet.</p>
              ) : (
                <div className="mt-2 divide-y divide-line rounded-lg border border-line">
                  {own.map((a) => (
                    <div key={a.credential_id} className="flex items-center justify-between gap-3 p-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm text-fg">{a.user}</div>
                        <div className="truncate font-mono text-xs text-muted">
                          {a.username || "(no username)"}
                          {a.age_days > 180 && (
                            <span className="ml-2 text-warn">unchanged {a.age_days}d</span>
                          )}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setEditing({ userID: a.user_id!, username: a.username, injection: a.injection })}
                        >
                          Rotate
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => remove.mutate(a.user_id!)}>
                          <IconTrash size={14} />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {inherited.length > 0 && (
              <div>
                <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">
                  Inherited from asset groups
                </h4>
                <p className="mt-1 text-xs text-muted">
                  Bound once on a group and working across everything beneath it. Edit them on the group.
                </p>
                <div className="mt-2 divide-y divide-line rounded-lg border border-line">
                  {inherited.map((a) => (
                    <div key={a.credential_id} className="flex items-center justify-between gap-3 p-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm text-fg">{a.user}</div>
                        <div className="truncate font-mono text-xs text-muted">{a.username}</div>
                      </div>
                      <Badge tone="neutral">{a.group_name}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {unbound.length > 0 && (
              <div>
                <h4 className="text-2xs font-semibold uppercase tracking-wider text-faint">Add an account</h4>
                <div className="mt-2">
                  <Select
                    value=""
                    onChange={(e) =>
                      e.target.value &&
                      setEditing({ userID: e.target.value, username: "", injection: defaultInjectionFor(device.scheme) })
                    }
                  >
                    <option value="">Choose somebody…</option>
                    {unbound.map((p) => (
                      <option key={p.user_id} value={p.user_id}>
                        {p.email}
                      </option>
                    ))}
                  </Select>
                </div>
              </div>
            )}
          </>
        )}

        <div className="flex justify-end">
          <Button variant="ghost" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>

      {editing && (
        <AccountEditor
          device={device}
          userID={editing.userID}
          initialUsername={editing.username}
          initialInjection={editing.injection}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void qc.invalidateQueries({ queryKey: ["device-accounts", device.id] });
            void qc.invalidateQueries({ queryKey: ["device-whoami", device.id] });
          }}
        />
      )}
    </Modal>
  );
}

function AccountEditor({
  device,
  userID,
  initialUsername,
  initialInjection,
  onClose,
  onSaved,
}: {
  device: Device;
  userID: string;
  initialUsername: string;
  initialInjection: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [username, setUsername] = useState(initialUsername);
  const [secret, setSecret] = useState("");
  // Carried explicitly, and seeded from what this account is already bound with.
  // The dialog used to send no method at all, and the server resolved an absent
  // one to the protocol's default — so rotating an ssh-key account turned it
  // into ssh-password with the PEM key still in the vault, reported success, and
  // broke the next connect. The server now leaves an omitted method alone; this
  // sends it anyway, because a rotation dialog that cannot show how the secret is
  // used is asking somebody to change a thing they cannot see.
  const [injection, setInjection] = useState(initialInjection || defaultInjectionFor(device.scheme));
  const methods = injectionMethodsFor(device.scheme);
  const existing = !!initialUsername;

  const save = useMutation({
    mutationFn: async () =>
      api.put(`/devices/${device.id}/accounts/${userID}`, {
        username,
        secret,
        injection,
        name: username || "per-user account",
      }),
    onSuccess: () => {
      toast.success(existing ? "Account rotated" : "Account bound");
      onSaved();
    },
    onError: (e) => toast.error(problemDetail(e, "Could not save the account")),
  });

  // Creating needs a secret; rotating may leave it blank to keep the stored one,
  // because the console never echoes a secret back to be re-sent.
  const canSave = username.trim().length > 0 && (existing || secret.length > 0);

  return (
    <Modal onClose={onClose} title={existing ? "Rotate account" : "Bind account"} icon={IconKey}>
      <div className="space-y-4">
        <Field label="Account on the device" hint="The login that exists on the target, e.g. jsmith-admin.">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="jsmith-admin" autoFocus />
        </Field>
        {methods.length > 0 && (
          <Field label="How it authenticates" hint={methods.find((m) => m.value === injection)?.hint}>
            <Select value={injection} onChange={(e) => setInjection(e.target.value)}>
              {methods.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <Field
          label="Secret"
          hint={existing ? "Leave blank to keep the current one." : "Stored encrypted and never shown again."}
        >
          <Input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={existing ? "•••••••• (unchanged)" : ""}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!canSave} loading={save.isPending} onClick={() => save.mutate()}>
            <IconCheck size={15} /> Save
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export type { Role };
