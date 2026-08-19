import { useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { Account, AssetGroup, Device, UserRow } from "@/lib/types";
import { MIXED_INJECTION, injectionMethodsFor } from "@/lib/types";
import {
  Badge, Button, EmptyState, ErrorNote, Field, Hairline, Input, Modal, Panel,
  Select, Skeleton, Spinner, Textarea,
} from "@/components/ui";
import { IconAlert, IconClock, IconFolder, IconKey, IconPlus, IconTrash, IconUsers } from "@/components/icons";
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
  const [editing, setEditing] = useState<{ userID: string; username: string; injection: string } | null>(null);
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
      {/* An empty picker is not an answer. It looks identical whether there are
          no groups, the list failed to load, or you are not allowed to see it,
          and the operator is left clicking a control that does nothing. Each
          case says which it is. */}
      {groups.isLoading ? (
        <Skeleton className="h-9" />
      ) : groups.error ? (
        <ErrorNote message={problemDetail(groups.error, "Could not load asset groups")} />
      ) : (groups.data ?? []).length === 0 ? (
        <EmptyState
          icon={IconFolder}
          title="No asset groups yet"
          message="Group accounts need a group to bind to. Groups are created on a device — open any device, and add it to a new group from the Groups field."
          action={
            <Link to="/devices" className="text-sm font-medium text-accent hover:underline">
              Go to devices
            </Link>
          }
        />
      ) : (
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
      )}

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
                    <Button size="sm" variant="ghost" onClick={() => setEditing({ userID: a.user_id!, username: a.username, injection: a.injection })}>
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
            <Select value="" onChange={(e) => e.target.value && setEditing({ userID: e.target.value, username: "", injection: "" })}>
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
          initialInjection={editing.injection}
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
  initialInjection,
  onClose,
  onSaved,
}: {
  groupID: string;
  userID: string;
  initialUsername: string;
  initialInjection: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [username, setUsername] = useState(initialUsername);
  const [secret, setSecret] = useState("");
  // Seeded from what the account is already bound with. This was hardcoded to
  // "ssh-password", so opening Rotate on an account bound with a private key or
  // an API token and pressing Save silently rewrote the method — the dialog
  // showed the wrong answer and then stored it.
  const [injection, setInjection] = useState(initialInjection || "ssh-password");
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
        {/* The list comes from MIXED_INJECTION rather than being written out
            here: this copy was missing the Authorization-header method, so a
            group of API-token devices could not be bound from this dialog at
            all. A group holds devices of mixed protocols, so the choice is
            checked per device when it is actually used. */}
        <Field
          label="How it authenticates"
          hint={MIXED_INJECTION.find((m) => m.value === injection)?.hint}
        >
          <Select value={injection} onChange={(e) => setInjection(e.target.value)}>
            {MIXED_INJECTION.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
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

// PersonRow is one line of the import as it is being built. key exists so a row
// keeps its identity across removals — index-keyed inputs swap their contents
// when a row above them is deleted, which with secrets in them is worse than
// cosmetic.
interface PersonRow {
  key: number;
  userID: string;
  username: string;
  secret: string;
}

// BulkImport binds many per-user accounts at once.
//
// It used to ask for hand-written CSV whose rows each carried a raw device_id or
// group_id — UUIDs nobody has memorized and which this console is the only place
// to look up, so using the feature meant copying identifiers out of one screen
// into a text box on another and counting commas. The target and the injection
// method are the same for every row of a real import anyway, so they are chosen
// once, by name, and a row carries only what actually differs per person.
//
// Pasting a list still works, because that is what comes out of whatever system
// already knows which account belongs to whom — but it is three columns of
// things a human knows, not six with two identifiers.
function BulkImport() {
  const qc = useQueryClient();
  const [target, setTarget] = useState("");
  const [injection, setInjection] = useState("");
  const [rows, setRows] = useState<PersonRow[]>([{ key: 1, userID: "", username: "", secret: "" }]);
  const nextKey = useRef(2);
  const [pasting, setPasting] = useState(false);
  const [paste, setPaste] = useState("");
  const [pasteNote, setPasteNote] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  // The rows as sent, kept so a failure that comes back as "row 3" can be
  // reported against the person on it. Counting lines in a textarea to find out
  // who did not get an account is not a report.
  const [sent, setSent] = useState<PersonRow[]>([]);

  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data ?? [],
  });
  const devices = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: async () => (await api.get<{ data: Device[] }>("/devices")).data.data ?? [],
  });
  const people = useQuery<UserRow[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<{ data: UserRow[] }>("/users")).data.data ?? [],
  });

  const [kind, targetID] = splitTarget(target);
  const device = kind === "device" ? (devices.data ?? []).find((d) => d.id === targetID) : undefined;
  // A device knows its protocol, so only the methods that can authenticate it
  // are offered. A group does not — it holds devices of mixed schemes — so the
  // method is taken as given and checked per device at connect time.
  const methods = kind === "device" ? injectionMethodsFor(device?.scheme ?? "") : MIXED_INJECTION;
  const method = methods.find((m) => m.value === injection);

  const ready = useMemo(
    () => rows.filter((r) => r.userID && r.username.trim() && r.secret),
    [rows],
  );
  const incomplete = rows.length - ready.length;

  const run = useMutation({
    mutationFn: async () => {
      const accounts = ready.map((r) => ({
        user_id: r.userID,
        ...(kind === "device" ? { device_id: targetID } : { group_id: targetID }),
        username: r.username.trim(),
        secret: r.secret,
        injection,
        name: r.username.trim(),
      }));
      setSent(ready);
      return (await api.post<ImportResult>("/accounts/import", { accounts })).data;
    },
    onSuccess: (r) => {
      setResult(r);
      if (r.imported > 0) {
        toast.success(`Bound ${r.imported} account${r.imported === 1 ? "" : "s"}`);
        void qc.invalidateQueries({ queryKey: ["device-accounts"] });
        void qc.invalidateQueries({ queryKey: ["group-accounts"] });
        // Secrets do not linger in the form after they have been stored. The
        // rows that failed stay, because those are the ones still to fix.
        const failed = new Set(r.failed.map((f) => f.index));
        const keep = ready.filter((_, i) => failed.has(i));
        setRows(keep.length > 0 ? keep : [{ key: nextKey.current++, userID: "", username: "", secret: "" }]);
      }
    },
    onError: (e) => toast.error(problemDetail(e, "Import failed")),
  });

  const setRow = (key: number, patch: Partial<PersonRow>) =>
    setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...patch } : r)));

  const addRow = () =>
    setRows((rs) => [...rs, { key: nextKey.current++, userID: "", username: "", secret: "" }]);

  const applyPaste = () => {
    const byEmail = new Map((people.data ?? []).map((p) => [p.email.toLowerCase(), p.user_id]));
    const parsed: PersonRow[] = [];
    const unknown: string[] = [];
    for (const line of paste.split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      const [email, username, ...rest] = t.split(",").map((c) => c.trim());
      // "email,username,secret" — and the secret keeps any commas in it, because
      // splitting a password on punctuation would store a truncated one and the
      // failure would not show up until somebody could not log in.
      const secret = rest.join(",");
      const id = byEmail.get((email ?? "").toLowerCase());
      if (!id) {
        if (email) unknown.push(email);
        continue;
      }
      parsed.push({ key: nextKey.current++, userID: id, username: username ?? "", secret });
    }
    // Rows are replaced rather than appended: pasting twice after a correction
    // should not leave the first attempt behind to be imported alongside it.
    setRows(parsed.length > 0 ? parsed : [{ key: nextKey.current++, userID: "", username: "", secret: "" }]);
    setPaste("");
    setPasting(false);
    setResult(null);
    // Unmatched addresses are named here rather than sent and rejected: the
    // secret on that line would otherwise cross the wire to fail server-side.
    setPasteNote(
      unknown.length > 0
        ? `${parsed.length} row(s) added. No GuardRail user matches: ${unknown.join(", ")}`
        : `${parsed.length} row(s) added.`,
    );
  };

  const chooseTarget = (v: string) => {
    setTarget(v);
    setResult(null);
    const [k, id] = splitTarget(v);
    const d = k === "device" ? (devices.data ?? []).find((x) => x.id === id) : undefined;
    const list = k === "device" ? injectionMethodsFor(d?.scheme ?? "") : k === "group" ? MIXED_INJECTION : [];
    setInjection(list[0]?.value ?? "");
  };

  const noTargets = (groups.data ?? []).length === 0 && (devices.data ?? []).length === 0;

  return (
    <Panel title="Bulk import" icon={IconUsers} subtitle="Bind many accounts at once">
      {groups.isLoading || devices.isLoading ? (
        <Skeleton className="h-24" />
      ) : noTargets ? (
        <EmptyState
          icon={IconFolder}
          title="Nothing to bind to"
          message="Register a device first. Accounts are bound to a device, or to an asset group covering several."
        />
      ) : (
        <>
          <Field
            label="Bind these accounts on"
            hint="A group covers every device beneath it, including ones added later. A device binds just that one."
          >
            <Select value={target} onChange={(e) => chooseTarget(e.target.value)}>
              <option value="">Choose a group or device…</option>
              {(groups.data ?? []).length > 0 && (
                <optgroup label="Asset groups">
                  {(groups.data ?? []).map((g) => (
                    <option key={g.id} value={`group:${g.id}`}>
                      {g.name}
                    </option>
                  ))}
                </optgroup>
              )}
              {(devices.data ?? []).length > 0 && (
                <optgroup label="Devices">
                  {(devices.data ?? []).map((d) => (
                    <option key={d.id} value={`device:${d.id}`}>
                      {d.name} ({d.scheme})
                    </option>
                  ))}
                </optgroup>
              )}
            </Select>
          </Field>

          {target && (
            <Field label="How the secret authenticates" hint={method?.hint}>
              {methods.length === 0 ? (
                <ErrorNote
                  message={`GuardRail has no injection method for ${device?.scheme || "this protocol"}, so an account cannot be bound here.`}
                />
              ) : (
                <Select value={injection} onChange={(e) => setInjection(e.target.value)}>
                  {methods.map((m) => (
                    <option key={m.value} value={m.value}>
                      {m.label}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}

          {target && methods.length > 0 && (
            <>
              <Hairline />
              <div className="mt-3 flex items-center justify-between gap-3">
                <span className="label mb-0">People</span>
                <button
                  type="button"
                  className="text-xs font-medium text-accent hover:underline"
                  onClick={() => {
                    setPasting((v) => !v);
                    setPasteNote("");
                  }}
                >
                  {pasting ? "Cancel paste" : "Paste a list"}
                </button>
              </div>

              {pasting ? (
                <div className="mt-2">
                  <Textarea
                    rows={5}
                    autoFocus
                    className="font-mono text-xs"
                    value={paste}
                    onChange={(e) => setPaste(e.target.value)}
                    placeholder={"alice@corp.com,alice-admin,s3cret\nbob@corp.com,bob-admin,hunter2"}
                  />
                  <p className="mt-1.5 text-xs text-faint">
                    One person per line: email, the account name on the device, then the secret. No header.
                  </p>
                  <div className="mt-2 flex justify-end">
                    <Button size="sm" variant="primary" disabled={!paste.trim()} onClick={applyPaste}>
                      Add rows
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="mt-2 space-y-2">
                  {/* The email identifies the row, so it gets the widest column: a
                      select truncated mid-address makes two people sharing a prefix
                      indistinguishable. */}
                  {rows.map((r) => (
                    <div
                      key={r.key}
                      className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)_minmax(0,1fr)_auto]"
                    >
                      <Select value={r.userID} onChange={(e) => setRow(r.key, { userID: e.target.value })}>
                        <option value="">Person…</option>
                        {(people.data ?? []).map((p) => (
                          <option key={p.user_id} value={p.user_id}>
                            {p.email}
                          </option>
                        ))}
                      </Select>
                      <Input
                        value={r.username}
                        placeholder="account on the device"
                        onChange={(e) => setRow(r.key, { username: e.target.value })}
                      />
                      <Input
                        type="password"
                        value={r.secret}
                        placeholder="secret"
                        onChange={(e) => setRow(r.key, { secret: e.target.value })}
                      />
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label="Remove row"
                        disabled={rows.length === 1}
                        onClick={() => setRows((rs) => rs.filter((x) => x.key !== r.key))}
                      >
                        <IconTrash size={14} />
                      </Button>
                    </div>
                  ))}
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
                    onClick={addRow}
                  >
                    <IconPlus size={12} /> Add another
                  </button>
                </div>
              )}

              {pasteNote && <p className="mt-2 text-xs text-muted">{pasteNote}</p>}

              <div className="mt-3 flex items-center justify-between gap-3">
                <span className="text-xs text-muted">
                  {ready.length} ready
                  {incomplete > 0 && <span className="text-faint"> · {incomplete} incomplete, skipped</span>}
                  {ready.length > 500 && <span className="text-danger"> · at most 500 at a time</span>}
                </span>
                <Button
                  variant="primary"
                  disabled={ready.length === 0 || ready.length > 500}
                  loading={run.isPending}
                  onClick={() => run.mutate()}
                >
                  Import {ready.length || ""}
                </Button>
              </div>
            </>
          )}
        </>
      )}

      {result && (
        <>
          <Hairline />
          <div className="mt-3 text-sm">
            <div className="text-fg">
              <Badge tone="success">{result.imported} imported</Badge>{" "}
              {result.failed.length > 0 && <Badge tone="danger">{result.failed.length} failed</Badge>}
            </div>
            {/* Every failure is named with the person it belongs to. An import
                that quietly binds thirty-nine of forty is worse than one that
                says who was left out. */}
            {result.failed.length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-muted">
                {result.failed.map((f) => (
                  <li key={f.index}>
                    {emailOf(people.data, sent[f.index]?.userID) ?? `Row ${f.index + 1}`}:{" "}
                    <span className="text-danger">{f.error}</span>
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

// splitTarget turns "group:<uuid>" into ["group", "<uuid>"]. The kind is carried
// in the value because one picker listing both groups and devices is one fewer
// control than a kind toggle beside a list, and the two are never ambiguous.
function splitTarget(v: string): [string, string] {
  const i = v.indexOf(":");
  return i < 0 ? ["", ""] : [v.slice(0, i), v.slice(i + 1)];
}

function emailOf(people: UserRow[] | undefined, userID: string | undefined): string | undefined {
  if (!userID) return undefined;
  return (people ?? []).find((p) => p.user_id === userID)?.email;
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
