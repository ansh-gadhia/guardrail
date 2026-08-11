import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import { TOKEN_SCOPES, type APIToken, type NewAPIToken } from "@/lib/types";
import { plausibleDate } from "@/lib/dates";
import { Panel, Field, Badge, Modal, ErrorNote, EmptyState, Spinner } from "@/components/ui";
import { IconKey, IconPlus, IconTrash, IconClipboard, IconCheck, IconLock } from "@/components/icons";
import { toast } from "@/components/Toast";

/* ---- helpers ---------------------------------------------------------------- */

type TokenState = "active" | "revoked" | "expired";

function tokenState(t: APIToken): TokenState {
  if (t.revoked) return "revoked";
  const exp = plausibleDate(t.expires_at);
  if (exp && exp.getTime() <= Date.now()) return "expired";
  return "active";
}

const STATE_TONE = { active: "success", revoked: "danger", expired: "warn" } as const;

/** Coarse relative time. A token's last-used stamp is throttled to a minute on
 * the server, so anything finer than this would be reporting precision the data
 * does not have. */
function ago(iso?: string): string | null {
  const d = plausibleDate(iso);
  if (!d) return null;
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

function when(iso?: string): string {
  return plausibleDate(iso)?.toLocaleDateString() ?? "—";
}

/** Copy button that confirms in place.
 *
 * The tick is the whole point: a copy that gives no feedback gets pressed twice,
 * and on the one-time reveal the second press happens after the panel is gone. */
function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={className ?? "btn-ghost"}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          window.setTimeout(() => setDone(false), 1600);
        } catch {
          // Clipboard access can be refused (permissions, a non-secure origin).
          // Say so rather than showing a tick for something that did not happen —
          // the value is on screen and can still be selected by hand.
          toast.warn("Couldn't reach the clipboard — select the text and copy it");
        }
      }}
    >
      {done ? <IconCheck size={14} /> : <IconClipboard size={14} />}
      {done ? "Copied" : label}
    </button>
  );
}

/* ---- the one-time reveal ----------------------------------------------------
 *
 * The only moment this value exists anywhere outside the caller's clipboard. It
 * stays until dismissed — no auto-hide, no toast — because a person who looks
 * away and comes back to an empty screen has lost the credential for good.
 */
function TokenReveal({ token, onDismiss }: { token: NewAPIToken; onDismiss: () => void }) {
  return (
    <div className="rounded-xl border border-accent/30 bg-accent-soft/30 p-4">
      <div className="flex items-start gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent text-accent-fg">
          <IconKey size={16} />
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="font-display text-sm font-semibold text-fg">
            {token.name} is ready
          </h3>
          <p className="mt-0.5 text-xs text-muted">
            Copy it now. Only a hash is stored, so this is the one and only time it can be shown.
          </p>

          <div className="mt-3 flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2">
            <code className="min-w-0 flex-1 select-all break-all font-mono text-sm text-accent">{token.token}</code>
            <CopyButton value={token.token} className="btn-primary btn-sm shrink-0" />
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            {token.scopes.map((s) => (
              <Badge key={s} tone="neutral">{s}</Badge>
            ))}
          </div>

          <div className="mt-4 flex justify-end">
            <button className="btn-ghost" onClick={onDismiss}>
              I've saved it
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---- create dialog ----------------------------------------------------------- */

function CreateTokenModal({ onClose, onCreated }: { onClose: () => void; onCreated: (t: NewAPIToken) => void }) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["device:read"]);
  const [expires, setExpires] = useState("");

  const toggle = (key: string) =>
    setScopes((cur) => (cur.includes(key) ? cur.filter((s) => s !== key) : [...cur, key]));

  const create = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { name: name.trim(), scopes };
      // A date input gives a bare day; the API wants RFC3339. End of that day in
      // the browser's own zone, so "expires 31 Dec" means the whole of the 31st
      // to the person who typed it rather than midnight at its start.
      if (expires) {
        const d = new Date(`${expires}T23:59:59`);
        body.expires_at = d.toISOString();
      }
      return (await api.post<NewAPIToken>("/api-tokens", body)).data;
    },
    onSuccess: (t) => {
      onCreated(t);
      toast.success(`Created ${t.name}`);
    },
  });

  const today = new Date().toISOString().slice(0, 10);
  const canSubmit = name.trim().length > 0 && scopes.length > 0 && !create.isPending;

  return (
    <Modal
      title="New API token"
      icon={IconKey}
      size="lg"
      onClose={onClose}
      footer={
        <>
          <button className="btn-ghost" disabled={create.isPending} onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!canSubmit} onClick={() => create.mutate()}>
            {create.isPending ? "Creating…" : "Create token"}
          </button>
        </>
      }
    >
      {create.isError && (
        <div className="mb-4">
          <ErrorNote message={problemDetail(create.error, "Could not create the token")} />
        </div>
      )}

      <Field label="Name" hint="What will use this token. It appears in the audit log.">
        <input
          className="input"
          autoFocus
          placeholder="noc-dashboard"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>

      <Field
        label="Expires"
        hint="Leave empty for a token that does not expire. Revoking works either way."
      >
        <input className="input" type="date" min={today} value={expires} onChange={(e) => setExpires(e.target.value)} />
      </Field>

      <div className="mb-2 mt-4">
        <div className="text-xs font-medium text-fg">What it can read</div>
        <p className="mt-0.5 text-xs text-muted">
          Reads only — a token can never open a session or change anything. Grant the least that does the job.
        </p>
      </div>

      <div className="grid gap-1.5 sm:grid-cols-2">
        {TOKEN_SCOPES.map((s) => {
          const on = scopes.includes(s.key);
          return (
            <label
              key={s.key}
              className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5 transition ${
                on ? "border-accent/40 bg-accent-soft/30" : "border-line bg-surface-2/40 hover:border-line-strong"
              }`}
            >
              <input
                type="checkbox"
                className="mt-0.5"
                style={{ accentColor: "rgb(var(--accent))" }}
                checked={on}
                onChange={() => toggle(s.key)}
              />
              <span className="min-w-0">
                <span className="block text-xs font-medium text-fg">{s.label}</span>
                <span className="block text-2xs text-muted">{s.blurb}</span>
                <code className="mt-0.5 block font-mono text-2xs text-faint">{s.key}</code>
              </span>
            </label>
          );
        })}
      </div>

      {scopes.length === 0 && (
        <p className="mt-3 text-xs text-warn">Pick at least one — a token with no scopes can read nothing.</p>
      )}
    </Modal>
  );
}

/* ---- the tab ------------------------------------------------------------------ */

export function ApiTokensTab() {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [fresh, setFresh] = useState<NewAPIToken | null>(null);
  const [revoking, setRevoking] = useState<APIToken | null>(null);

  const tokens = useQuery<APIToken[]>({
    queryKey: ["api-tokens"],
    queryFn: async () => (await api.get<{ data: APIToken[] }>("/api-tokens")).data.data,
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => api.delete(`/api-tokens/${id}`),
    onSuccess: () => {
      toast.warn(`Revoked ${revoking?.name ?? "token"}`);
      setRevoking(null);
      void qc.invalidateQueries({ queryKey: ["api-tokens"] });
    },
  });

  // Active first, then by age. The list is a working set: the thing you came to
  // revoke is almost never the oldest revoked row.
  const rows = useMemo(() => {
    const list = tokens.data ?? [];
    return [...list].sort((a, b) => {
      const sa = tokenState(a) === "active" ? 0 : 1;
      const sb = tokenState(b) === "active" ? 0 : 1;
      if (sa !== sb) return sa - sb;
      return (plausibleDate(b.created_at)?.getTime() ?? 0) - (plausibleDate(a.created_at)?.getTime() ?? 0);
    });
  }, [tokens.data]);

  const example = `curl -sk ${window.location.origin}/api/v1/status/devices \\
     -H "Authorization: Bearer ${fresh?.token ?? "grt_…"}"`;

  return (
    <div className="max-w-4xl space-y-4">
      {fresh && (
        <TokenReveal
          token={fresh}
          onDismiss={() => {
            setFresh(null);
            void qc.invalidateQueries({ queryKey: ["api-tokens"] });
          }}
        />
      )}

      <Panel
        title="API tokens"
        subtitle="Long-lived credentials for scripts and dashboards — no login, no expiry unless you set one"
        icon={IconKey}
        actions={
          <button className="btn-primary btn-sm shrink-0" onClick={() => setCreating(true)}>
            <IconPlus size={14} />
            New token
          </button>
        }
      >
        {tokens.isLoading && <Spinner />}
        {tokens.isError && <ErrorNote message={problemDetail(tokens.error, "Could not load tokens")} />}

        {tokens.data && rows.length === 0 && (
          <EmptyState
            icon={IconKey}
            title="No API tokens"
            message="Create one to let a monitoring board or a script read the estate without signing in as a person."
            action={
              <button className="btn-primary" onClick={() => setCreating(true)}>
                <IconPlus size={14} />
                New token
              </button>
            }
          />
        )}

        {rows.length > 0 && (
          <div className="divide-y divide-line">
            {rows.map((t) => {
              const state = tokenState(t);
              const used = ago(t.last_used_at);
              return (
                <div key={t.id} className="flex flex-wrap items-start gap-3 py-3 first:pt-0 last:pb-0">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium text-fg">{t.name}</span>
                      <Badge tone={STATE_TONE[state]} dot>
                        {state}
                      </Badge>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                      <code className="font-mono text-faint">{t.prefix}…</code>
                      <span>Created {when(t.created_at)}</span>
                      {/* "Never used" is the useful signal at cleanup time: it is
                          the difference between a token to revoke and one that
                          something depends on. */}
                      <span className={used ? "" : "text-faint"}>{used ? `Last used ${used}` : "Never used"}</span>
                      {t.expires_at && <span>Expires {when(t.expires_at)}</span>}
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {t.scopes.map((s) => (
                        <Badge key={s} tone="neutral">{s}</Badge>
                      ))}
                    </div>
                  </div>
                  {state !== "revoked" && (
                    <button
                      className="btn-ghost text-danger hover:bg-danger/10"
                      onClick={() => setRevoking(t)}
                      aria-label={`Revoke ${t.name}`}
                    >
                      <IconTrash size={14} />
                      Revoke
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      <Panel title="Using a token" subtitle="Send it as a bearer. It never needs refreshing." icon={IconLock}>
        <div className="flex items-start gap-2 rounded-lg border border-line bg-surface-2/50 p-3">
          <pre className="min-w-0 flex-1 overflow-x-auto font-mono text-xs leading-relaxed text-muted">{example}</pre>
          <CopyButton value={example} label="Copy" className="btn-ghost shrink-0" />
        </div>
        <p className="mt-3 text-xs text-muted">
          A token carries its scopes and nothing else. It is not tied to your account: changing your password or turning
          on two-factor leaves it working, and revoking it here stops it on the next request.
        </p>
      </Panel>

      {creating && (
        <CreateTokenModal
          onClose={() => setCreating(false)}
          onCreated={(t) => {
            setCreating(false);
            setFresh(t);
          }}
        />
      )}

      {revoking && (
        <Modal
          title={`Revoke ${revoking.name}?`}
          icon={IconTrash}
          onClose={() => setRevoking(null)}
          footer={
            <>
              <button className="btn-ghost" disabled={revoke.isPending} onClick={() => setRevoking(null)}>
                Cancel
              </button>
              <button className="btn-danger" disabled={revoke.isPending} onClick={() => revoke.mutate(revoking.id)}>
                {revoke.isPending ? "Revoking…" : "Revoke token"}
              </button>
            </>
          }
        >
          <p className="text-sm text-muted">
            Anything using <span className="font-mono text-fg">{revoking.prefix}…</span> stops working on its next
            request. This cannot be undone — issue a new token if you need one again.
          </p>
          {revoke.isError && (
            <div className="mt-3">
              <ErrorNote message={problemDetail(revoke.error, "Could not revoke the token")} />
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
