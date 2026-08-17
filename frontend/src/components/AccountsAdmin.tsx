import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Account, AssetGroup, UserRow } from "@/lib/types";
import {
  Badge, Button, EmptyState, ErrorNote, Field, Hairline, Input, Modal, Panel,
  Select, Spinner, Textarea,
} from "@/components/ui";
import { IconAlert, IconFolder, IconKey, IconTrash, IconUsers, IconClock } from "@/components/icons";
import { toast } from "@/components/Toast";

// Per-user accounts, administered across the estate.
//
// The device page manages one device's accounts. This is the other half: bind
// once against an asset group and cover everything beneath it, import in bulk,
// and find the secrets nobody has changed in a year.

export function AccountsAdmin() {
  return (
    <div className="space-y-5">
      <GroupAccounts />
      <div className="grid gap-5 lg:grid-cols-2">
        <BulkImport />
        <StaleSecrets />
      </div>
    </div>
  );
}

// ---- group-scoped accounts ------------------------------------------------

// The feature that makes per-user accounts survive scale. `jsmith-admin` almost
// certainly works on all thirty access switches; binding per device is thirty
// rows per person and nobody maintains that.
function GroupAccounts() {
  const [groupID, setGroupID] = useState("");
  const [editing, setEditing] = useState<{ userID: string; username: string } | null>(null);
  const qc = useQueryClient();

  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data ?? [],
  });

  const people = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data ?? [],
  });

  const accounts = useQuery({
    queryKey: ["group-accounts", groupID],
    queryFn: async () => (await api.get<{ accounts: Account[] }>(`/asset-groups/${groupID}/accounts`)).data.accounts ?? [],
    enabled: !!groupID,
  });

  const remove = useMutation({
    mutationFn: async (userID: string) => api.delete(`/asset-groups/${groupID}/accounts/${userID}`),
    onSuccess: () => {
      toast.success("Account removed from the group");
      void qc.invalidateQueries({ queryKey: ["group-accounts", groupID] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not remove the account")),
  });

  const bound = new Set((accounts.data ?? []).map((a) => a.user_id));
  const unbound = (people.data ?? []).filter((p) => !bound.has(p.user_id));

  return (
    <Panel
      title="Accounts on asset groups"
      icon={IconFolder}
      subtitle="Bind a person's account once on a group and it works on every device beneath it — including devices added later"
    >
      <Field label="Group" hint="Nearest group wins: an account bound on “Datacentre / Core” beats one bound on “Datacentre”.">
        <Select value={groupID} onChange={(e) => setGroupID(e.target.value)}>
          <option value="">Choose an asset group…</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </Select>
      </Field>

      {!groupID ? null : accounts.isLoading ? (
        <div className="mt-4">
          <Spinner />
        </div>
      ) : accounts.error ? (
        <div className="mt-4">
          <ErrorNote message={problemDetail(accounts.error, "Could not load group accounts")} />
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          {(accounts.data ?? []).length === 0 ? (
            <p className="text-sm text-muted">Nobody has an account bound on this group.</p>
          ) : (
            <div className="divide-y divide-line rounded-lg border border-line">
              {(accounts.data ?? []).map((a) => (
                <div key={a.credential_id} className="flex items-center justify-between gap-3 p-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm text-fg">{a.user}</div>
                    <div className="truncate font-mono text-xs text-muted">
                      {a.username || "(no username)"}
                      {a.age_days > 180 && <span className="ml-2 text-warn">unchanged {a.age_days}d</span>}
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <Button size="sm" variant="ghost" onClick={() => setEditing({ userID: a.user_id!, username: a.username })}>
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

          {unbound.length > 0 && (
            <Select value="" onChange={(e) => e.target.value && setEditing({ userID: e.target.value, username: "" })}>
              <option value="">Add somebody…</option>
              {unbound.map((p) => (
                <option key={p.user_id} value={p.user_id}>
                  {p.email}
                </option>
              ))}
            </Select>
          )}
        </div>
      )}

      {editing && groupID && (
        <GroupAccountEditor
          groupID={groupID}
          userID={editing.userID}
          initialUsername={editing.username}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void qc.invalidateQueries({ queryKey: ["group-accounts", groupID] });
          }}
        />
      )}
    </Panel>
  );
}

function GroupAccountEditor({
  groupID,
  userID,
  initialUsername,
  onClose,
  onSaved,
}: {
  groupID: string;
  userID: string;
  initialUsername: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [username, setUsername] = useState(initialUsername);
  const [secret, setSecret] = useState("");
  const [injection, setInjection] = useState("ssh-password");
  const existing = !!initialUsername;

  const save = useMutation({
    mutationFn: async () =>
      api.put(`/asset-groups/${groupID}/accounts/${userID}`, {
        username,
        secret,
        injection,
        name: username || "per-user account",
      }),
    onSuccess: () => {
      toast.success(existing ? "Account rotated" : "Account bound to the group");
      onSaved();
    },
    onError: (e) => toast.error(problemDetail(e, "Could not save the account")),
  });

  const canSave = username.trim().length > 0 && (existing || secret.length > 0);

  return (
    <Modal onClose={onClose} title={existing ? "Rotate group account" : "Bind account to group"} icon={IconKey}>
      <div className="space-y-4">
        <Field label="Account on the devices" hint="The login that exists on the targets, e.g. jsmith-admin.">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="jsmith-admin" autoFocus />
        </Field>
        <Field
          label="How it authenticates"
          hint="A group holds devices of mixed protocols, so this is checked per device when it is actually used."
        >
          <Select value={injection} onChange={(e) => setInjection(e.target.value)}>
            <option value="ssh-password">SSH password</option>
            <option value="ssh-key">SSH private key</option>
            <option value="password">Desktop / telnet password</option>
            <option value="basic">HTTP Basic</option>
            <option value="form">Login form</option>
          </Select>
        </Field>
        <Field label="Secret" hint={existing ? "Leave blank to keep the current one." : "Stored encrypted and never shown again."}>
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
            Save
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ---- bulk import ----------------------------------------------------------

interface ImportResult {
  imported: number;
  failed: { index: number; error: string }[];
}

// Forty people across twenty devices is not a form-fill job. CSV because that is
// what comes out of whatever system already knows which account belongs to whom.
function BulkImport() {
  const qc = useQueryClient();
  const [csv, setCsv] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);

  const rows = useMemo(() => parseCSV(csv), [csv]);

  const run = useMutation({
    mutationFn: async () => (await api.post<ImportResult>("/accounts/import", { accounts: rows.rows })).data,
    onSuccess: (r) => {
      setResult(r);
      if (r.imported > 0) {
        toast.success(`Bound ${r.imported} account${r.imported === 1 ? "" : "s"}`);
        void qc.invalidateQueries({ queryKey: ["device-accounts"] });
        void qc.invalidateQueries({ queryKey: ["group-accounts"] });
      }
    },
    onError: (e) => toast.error(problemDetail(e, "Import failed")),
  });

  return (
    <Panel title="Bulk import" icon={IconUsers} subtitle="Bind many accounts at once">
      <p className="text-sm text-muted">
        One row per account. Header required. Give each row either a <span className="font-mono">device_id</span> or a{" "}
        <span className="font-mono">group_id</span>.
      </p>
      <pre className="mt-2 overflow-x-auto rounded-lg border border-line bg-surface-2 p-2 text-2xs text-muted">
user_email,device_id,group_id,username,secret,injection{"\n"}
alice@corp.com,,4f1c…,alice-admin,s3cret,ssh-password
      </pre>
      <div className="mt-3">
        <Textarea
          rows={6}
          className="font-mono text-xs"
          value={csv}
          onChange={(e) => {
            setCsv(e.target.value);
            setResult(null);
          }}
          placeholder="user_email,device_id,group_id,username,secret,injection"
        />
      </div>
      {rows.error && <p className="mt-2 text-xs text-danger">{rows.error}</p>}
      {!rows.error && rows.rows.length > 0 && (
        <p className="mt-2 text-xs text-muted">{rows.rows.length} row(s) ready.</p>
      )}
      <div className="mt-3 flex justify-end">
        <Button
          variant="primary"
          disabled={rows.rows.length === 0 || !!rows.error}
          loading={run.isPending}
          onClick={() => run.mutate()}
        >
          Import {rows.rows.length || ""}
        </Button>
      </div>

      {result && (
        <>
          <Hairline />
          <div className="mt-3 text-sm">
            <div className="text-fg">
              <Badge tone="success">{result.imported} imported</Badge>{" "}
              {result.failed.length > 0 && <Badge tone="danger">{result.failed.length} failed</Badge>}
            </div>
            {/* Every failure is named with its row. An import that quietly binds
                thirty-nine of forty is worse than one that says which line was
                wrong. */}
            {result.failed.length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-muted">
                {result.failed.map((f) => (
                  <li key={f.index}>
                    Row {f.index + 1}: <span className="text-danger">{f.error}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </Panel>
  );
}

interface ImportRow {
  user_email?: string;
  user_id?: string;
  device_id?: string;
  group_id?: string;
  username?: string;
  secret?: string;
  injection?: string;
  name?: string;
}

// parseCSV is deliberately strict about the header and forgiving about
// whitespace: a header typo should be reported here, not discovered as forty
// failed rows after the secrets have already crossed the wire.
function parseCSV(text: string): { rows: ImportRow[]; error?: string } {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length === 0) return { rows: [] };
  const header = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const known = ["user_email", "user_id", "device_id", "group_id", "username", "secret", "injection", "name"];
  const unknown = header.filter((h) => h && !known.includes(h));
  if (unknown.length > 0) return { rows: [], error: `Unknown column(s): ${unknown.join(", ")}` };
  if (!header.includes("user_email") && !header.includes("user_id")) {
    return { rows: [], error: "Needs a user_email or user_id column" };
  }
  const rows: ImportRow[] = [];
  for (const line of lines.slice(1)) {
    const cells = line.split(",");
    const row: ImportRow = {};
    header.forEach((h, i) => {
      const v = (cells[i] ?? "").trim();
      if (v) (row as Record<string, string>)[h] = v;
    });
    rows.push(row);
  }
  return { rows };
}

// ---- rotation age ---------------------------------------------------------

// Per-user accounts multiply the number of secrets in the vault by the number of
// people. Stale ones are how that rots, so the age is surfaced rather than left
// to be discovered.
function StaleSecrets() {
  const [days, setDays] = useState(180);
  const q = useQuery({
    queryKey: ["stale-credentials", days],
    queryFn: async () =>
      (await api.get<{ credentials: { id: string; name: string; username: string; age_days: number }[] }>(
        `/accounts/stale?days=${days}`,
      )).data.credentials ?? [],
  });

  return (
    <Panel
      title="Ageing secrets"
      icon={IconClock}
      subtitle="Credentials whose secret has not changed in a long time"
      actions={
        <Select value={days} onChange={(e) => setDays(Number(e.target.value))} className="w-auto">
          <option value={90}>90 days</option>
          <option value={180}>180 days</option>
          <option value={365}>1 year</option>
        </Select>
      }
    >
      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorNote message={problemDetail(q.error, "Could not load credential ages")} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState
          icon={IconKey}
          title="Nothing overdue"
          message={`Every stored secret has been changed within the last ${days} days.`}
        />
      ) : (
        <div className="divide-y divide-line">
          {(q.data ?? []).map((c) => (
            <div key={c.id} className="flex items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <div className="truncate text-sm text-fg">{c.name}</div>
                <div className="truncate font-mono text-xs text-muted">{c.username || "(no username)"}</div>
              </div>
              <Badge tone={c.age_days > 365 ? "danger" : "warn"}>
                <IconAlert size={12} /> {c.age_days}d
              </Badge>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
