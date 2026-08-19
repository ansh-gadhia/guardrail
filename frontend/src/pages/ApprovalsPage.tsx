import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, problemDetail } from "@/lib/api";
import type { AccessGrant, AccessRequest, GrantScope } from "@/lib/types";
import { useAuth } from "@/store/auth";
import {
  PageHero, Panel, Spinner, ErrorNote, EmptyState, Badge, Button, Modal,
  Field, Select, Textarea, Tabs, Hairline,
} from "@/components/ui";
import { IconCheck, IconClock, IconShield, IconAlert, IconTrash, IconAudit } from "@/components/icons";
import { toast } from "@/components/Toast";
import { plausibleDate } from "@/lib/dates";

// Approvals.
//
// Five views of one question, because "who may reach this device" gets asked in
// five different tenses: who is asking now, who is already in, who has ever been
// let in, what have I asked for, and what did somebody take without asking.

type Tab = "queue" | "open" | "history" | "mine" | "emergency";

export function ApprovalsPage() {
  const principal = useAuth((s) => s.principal);
  const canDecide = !!principal?.is_super_admin || !!principal?.permissions.includes("approval:decide");
  const canRead = canDecide || !!principal?.permissions.includes("approval:read");
  const [tab, setTab] = useState<Tab>(canDecide ? "queue" : "mine");

  // The waiting count rides on the tab label so an approver can see there is
  // something to do without opening it first.
  const pending = useQuery({
    queryKey: ["access-requests", "pending"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?pending=true")).data.requests ?? [],
    enabled: canDecide,
    refetchInterval: 30_000,
  });
  const waiting = pending.data?.length ?? 0;

  const tabs = [
    ...(canDecide
      ? [{ id: "queue", label: waiting > 0 ? `Awaiting decision (${waiting})` : "Awaiting decision", icon: IconClock }]
      : []),
    ...(canRead ? [{ id: "open", label: "Open access", icon: IconCheck }] : []),
    { id: "history", label: "History", icon: IconAudit },
    { id: "mine", label: "My requests", icon: IconShield },
    ...(canDecide ? [{ id: "emergency", label: "Emergency review", icon: IconAlert }] : []),
  ];

  return (
    <div>
      <PageHero
        icon={IconShield}
        eyebrow="Governance"
        title="Approvals"
        subtitle="Who may reach a gated device, for how long, and who said so"
        actions={
          principal && (
            <Badge tone="neutral">
              Your rank {principal.is_super_admin ? "— super admin" : principal.approval_level}
            </Badge>
          )
        }
      />
      <div className="mb-5">
        <Tabs tabs={tabs} active={tab} onChange={(t) => setTab(t as Tab)} />
      </div>
      {tab === "queue" && <QueueTab />}
      {tab === "open" && <OpenAccessTab canRevoke={canDecide} />}
      {tab === "history" && <HistoryTab />}
      {tab === "mine" && <MineTab />}
      {tab === "emergency" && <EmergencyTab />}
    </div>
  );
}

// ---- shared bits ----------------------------------------------------------

function statusTone(s: AccessRequest["status"]) {
  switch (s) {
    case "approved":
      return "success" as const;
    case "denied":
      return "danger" as const;
    case "pending":
      return "warn" as const;
    default:
      return "neutral" as const;
  }
}

// outcome says what actually happened, in the words somebody would use.
//
// "Expired" is split in two on purpose: a request nobody answered and an
// approval nobody used are different failures — the first is an approver
// problem, the second is not — and reporting both as "expired" hides which one
// an organization actually has.
function outcome(r: AccessRequest): { label: string; tone: "success" | "danger" | "warn" | "neutral" } {
  const wasApproved = (r.decisions ?? []).some((d) => d.decision === "approve");
  switch (r.status) {
    case "approved":
      return r.grant_scope === "always"
        ? { label: "Allowed — all time", tone: "success" }
        : { label: "Allowed — once", tone: "success" };
    case "denied":
      return { label: "Denied", tone: "danger" };
    case "cancelled":
      return { label: "Withdrawn", tone: "neutral" };
    case "expired":
      return wasApproved
        ? { label: "Approved, never used", tone: "warn" }
        : { label: "Expired unanswered", tone: "warn" };
    default:
      return { label: "Waiting", tone: "warn" };
  }
}

function countdown(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return "";
  if (ms <= 0) return "expired";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}m left`;
  return `${Math.round(mins / 60)}h left`;
}

function minutesLabel(m: number): string {
  return m < 60 ? `${m} min` : `${Math.round((m / 60) * 10) / 10} h`;
}

function windowLabel(r: AccessRequest): string {
  const m = r.granted_minutes ?? r.requested_minutes;
  // Name the shortening explicitly. An operator who asked for four hours and
  // got one needs to know before they start, not when the session ends.
  if (r.granted_minutes != null && r.granted_minutes < r.requested_minutes) {
    return `${minutesLabel(m)} (asked ${minutesLabel(r.requested_minutes)})`;
  }
  return minutesLabel(m);
}

// decidedBy names who allowed it — or says plainly that nobody did.
//
// An emergency has no approver by design, and rendering it as "approved by —"
// reads as missing data rather than as the thing that actually happened.
function decidedBy(r: AccessRequest): string {
  if (r.is_emergency) return "taken as emergency";
  const last = (r.decisions ?? []).at(-1);
  return last ? `approved by ${last.by}` : "no approver recorded";
}

function when(iso?: string): string {
  const d = plausibleDate(iso);
  return d ? d.toLocaleString() : "—";
}

function RequestCard({ r, children }: { r: AccessRequest; children?: React.ReactNode }) {
  // Defensive: an older server serializes an empty decision list as null, and a
  // governance screen that white-screens on it is a worse failure than a blank
  // row. The server sends [] now; this keeps a version skew survivable.
  const decisions = r.decisions ?? [];
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-fg">{r.requester}</span>
            <span className="text-muted">→</span>
            <span className="font-medium text-fg">{r.device}</span>
            {r.is_emergency && <Badge tone="danger">Emergency</Badge>}
            <Badge tone={statusTone(r.status)}>{r.status}</Badge>
            {r.min_approvals > 1 && (
              <Badge tone="neutral">
                {r.approvals} of {r.min_approvals} approvals
              </Badge>
            )}
            {r.escalated_level != null && <Badge tone="warn">Escalated</Badge>}
          </div>
          {/* The reason gets the most room on the row: it is the only field
              that actually informs the decision. */}
          <p className="mt-2 max-w-prose text-sm text-fg">{r.reason}</p>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
            <span>Wants {windowLabel(r)}</span>
            <span>Rank {r.requester_level}</span>
            <span>Asked {when(r.created_at)}</span>
            {r.status === "pending" && <span className="text-warn">{countdown(r.expires_at)}</span>}
          </div>
          {decisions.length > 0 && (
            <div className="mt-3 space-y-1 border-l-2 border-line pl-3 text-xs text-muted">
              {decisions.map((d, i) => (
                <div key={i}>
                  <span className={d.decision === "approve" ? "text-success" : "text-danger"}>
                    {d.decision === "approve" ? "Approved" : "Denied"}
                  </span>{" "}
                  by {d.by}
                  {d.note && <span className="text-fg"> — “{d.note}”</span>}
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">{children}</div>
      </div>
    </div>
  );
}

// ---- the queue ------------------------------------------------------------

function QueueTab() {
  const qc = useQueryClient();
  const [deciding, setDeciding] = useState<AccessRequest | null>(null);

  const q = useQuery({
    queryKey: ["access-requests", "pending"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?pending=true")).data.requests ?? [],
    // Somebody is waiting on this screen. Refresh often enough that a decision
    // made in another tab does not leave a stale row to be decided twice.
    refetchInterval: 15_000,
  });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorNote message={problemDetail(q.error, "Could not load the approval queue")} />;

  const list = q.data ?? [];
  if (list.length === 0) {
    return (
      <EmptyState
        icon={IconCheck}
        title="Nothing waiting"
        message="Requests to reach approval-gated devices appear here. You can only decide requests from people who rank below you — everything already settled is under History."
      />
    );
  }

  return (
    <div className="space-y-3">
      {list.map((r) => (
        <RequestCard key={r.id} r={r}>
          <Button variant="primary" size="sm" onClick={() => setDeciding(r)}>
            Decide
          </Button>
        </RequestCard>
      ))}
      {deciding && (
        <DecideModal
          request={deciding}
          onClose={() => setDeciding(null)}
          onDone={() => {
            setDeciding(null);
            void qc.invalidateQueries({ queryKey: ["access-requests"] });
            void qc.invalidateQueries({ queryKey: ["access-grants"] });
          }}
        />
      )}
    </div>
  );
}

// DecideModal is the three answers, spelled out.
//
// "Allow all time" is deliberately labelled with what it actually does: it is
// not an answer to this request, it is a standing grant that will still be there
// in six months.
function DecideModal({
  request,
  onClose,
  onDone,
}: {
  request: AccessRequest;
  onClose: () => void;
  onDone: () => void;
}) {
  const [minutes, setMinutes] = useState(request.requested_minutes);
  const [note, setNote] = useState("");

  const decide = useMutation({
    mutationFn: async (v: { decision: "approve" | "deny"; scope?: GrantScope }) =>
      api.post(`/access-requests/${request.id}/decide`, {
        decision: v.decision,
        scope: v.scope,
        minutes: v.decision === "approve" ? minutes : undefined,
        note,
      }),
    onSuccess: (_res, v) => {
      toast.success(v.decision === "approve" ? "Access approved" : "Request denied");
      onDone();
    },
    onError: (e) => toast.error(problemDetail(e, "Could not record the decision")),
  });

  const busy = decide.isPending;

  return (
    <Modal onClose={onClose} title="Decide this request" size="md">
      <div className="space-y-4">
        <div className="rounded-lg border border-line bg-surface-2 p-3 text-sm">
          <div className="font-medium text-fg">
            {request.requester} → {request.device}
          </div>
          <p className="mt-1 text-fg">{request.reason}</p>
          <p className="mt-1 text-xs text-muted">
            Asked for {request.requested_minutes} minutes · rank {request.requester_level}
            {request.min_approvals > 1 &&
              ` · needs ${request.min_approvals} approvals (${request.approvals} so far)`}
          </p>
        </div>

        <Field label="Grant for" hint="You can shorten what they asked for, but not extend it.">
          <Select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {[15, 30, 60, 120, 240, 480]
              .filter((m) => m <= request.requested_minutes)
              .map((m) => (
                <option key={m} value={m}>
                  {m < 60 ? `${m} minutes` : `${m / 60} hour${m > 60 ? "s" : ""}`}
                </option>
              ))}
          </Select>
        </Field>

        <Field label="Note" hint="Recorded against the decision and shown in History and the audit trail.">
          <Textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Optional" />
        </Field>

        <Hairline />

        <div className="space-y-2">
          <Button
            className="w-full justify-center"
            variant="primary"
            disabled={busy}
            onClick={() => decide.mutate({ decision: "approve", scope: "once" })}
          >
            Allow once — this session only
          </Button>
          {/* Bordered, not borderless. btn-subtle renders as bare text, which made
              the second of three choices read as a caption rather than a button —
              and it is the one with the longest-lived consequence. */}
          <Button
            className="w-full justify-center"
            variant="ghost"
            disabled={busy}
            onClick={() => decide.mutate({ decision: "approve", scope: "always" })}
          >
            Allow all time — standing access
          </Button>
          <p className="px-1 text-xs text-muted">
            Standing access never asks again. It appears under <b>Open access</b>, where it can be
            revoked — revoking also ends any session it is holding open.
          </p>
          <Button
            className="w-full justify-center"
            variant="danger"
            disabled={busy}
            onClick={() => decide.mutate({ decision: "deny" })}
          >
            Deny
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ---- open access ----------------------------------------------------------

// Everything that is open right now, both kinds in one place.
//
// Standing grants and live one-off approvals live in different tables, but they
// answer the same question — "who can reach a gated device without asking me
// first?" — and splitting them across two screens is how one of them stops being
// read.
function OpenAccessTab({ canRevoke }: { canRevoke: boolean }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState<AccessGrant | null>(null);

  const grants = useQuery({
    queryKey: ["access-grants"],
    queryFn: async () => (await api.get<{ grants: AccessGrant[] }>("/access-grants?live=true")).data.grants ?? [],
  });

  const approved = useQuery({
    queryKey: ["access-requests", "approved"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?status=approved&limit=200")).data.requests ?? [],
    refetchInterval: 30_000,
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => api.delete(`/access-grants/${id}`),
    onSuccess: () => {
      toast.success("Standing access revoked and any live session ended");
      setConfirm(null);
      void qc.invalidateQueries({ queryKey: ["access-grants"] });
      void qc.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not revoke")),
  });

  // A one-off approval is "open" while it can still be turned into a session.
  // Once redeemed it is the session that is open, so those are listed apart and
  // point at the session, which is where they can actually be ended.
  const unused = useMemo(
    () =>
      (approved.data ?? []).filter(
        (r) => r.grant_scope !== "always" && !r.session_id && new Date(r.expires_at).getTime() > Date.now(),
      ),
    [approved.data],
  );
  // session_active, not session_id. The request keeps pointing at the session
  // forever, and the request itself stays "approved" — a one-off is spent, not
  // re-decided, when it is used. Filtering on the pointer therefore listed every
  // one-off ever redeemed as though it were live: a screen that answers "who is
  // in a gated device right now" was naming people who left yesterday, next to a
  // window they were long past and a link to a session with nothing to end.
  //
  // A spent one-off is neither redeemable nor open, so it belongs to neither
  // panel here. History is where it is kept.
  const inUse = useMemo(
    () => (approved.data ?? []).filter((r) => r.grant_scope !== "always" && r.session_id && r.session_active),
    [approved.data],
  );

  if (grants.isLoading || approved.isLoading) return <Spinner />;
  if (grants.error) return <ErrorNote message={problemDetail(grants.error, "Could not load standing access")} />;

  const live = grants.data ?? [];

  return (
    <div className="space-y-4">
      <Panel
        title="Never expires — standing access"
        icon={IconCheck}
        subtitle="Granted with “Allow all time”. This is the list that answers “who can get in without a decision?”"
      >
        {live.length === 0 ? (
          <p className="text-sm text-muted">
            Nobody holds standing access. Every gated connect is decided one at a time.
          </p>
        ) : (
          <div className="divide-y divide-line">
            {live.map((g) => (
              <div key={g.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-fg">
                    {g.user} <span className="text-muted">on</span> {g.device}
                  </div>
                  <div className="mt-0.5 text-xs text-muted">
                    Granted by {g.granted_by || "—"} · {when(g.created_at)}
                    {g.expires_at ? ` · until ${when(g.expires_at)}` : " · no expiry"}
                  </div>
                </div>
                {canRevoke && (
                  <Button variant="ghost" size="sm" onClick={() => setConfirm(g)}>
                    <IconTrash size={14} /> Revoke
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title="One-off — approved, not yet used"
        icon={IconClock}
        subtitle="Allowed once and still redeemable. These lapse on their own if nobody connects."
      >
        {unused.length === 0 ? (
          <p className="text-sm text-muted">Nothing approved and waiting to be used.</p>
        ) : (
          <div className="divide-y divide-line">
            {unused.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-fg">
                    {r.requester} <span className="text-muted">on</span> {r.device}
                  </div>
                  <div className="mt-0.5 text-xs text-muted">
                    Allowed {windowLabel(r)} · {decidedBy(r)}
                  </div>
                </div>
                <Badge tone="warn">{countdown(r.expires_at)}</Badge>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {inUse.length > 0 && (
        <Panel
          title="One-off — in use"
          icon={IconShield}
          subtitle="Approved once and already turned into a session. End it from the session itself."
        >
          <div className="divide-y divide-line">
            {inUse.slice(0, 25).map((r) => (
              <div key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-fg">
                    {r.requester} <span className="text-muted">on</span> {r.device}
                  </div>
                  <div className="mt-0.5 text-xs text-muted">
                    Allowed {windowLabel(r)} · {decidedBy(r)}
                  </div>
                </div>
                {r.session_id && (
                  <Link
                    className="text-xs font-medium text-accent hover:underline"
                    to={`/sessions/${r.session_id}/view`}
                  >
                    Open session
                  </Link>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {confirm && (
        <Modal onClose={() => setConfirm(null)} title="Revoke standing access?">
          <p className="text-sm text-fg">
            {confirm.user} will have to ask for approval again to reach {confirm.device}.
          </p>
          <p className="mt-2 text-sm text-muted">
            Any session they currently hold on this device ends immediately — leaving it running would
            mean “allow once” quietly meant “allow for the next eight hours”.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirm(null)}>
              Keep it
            </Button>
            <Button variant="danger" disabled={revoke.isPending} onClick={() => revoke.mutate(confirm.id)}>
              Revoke and end sessions
            </Button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ---- history --------------------------------------------------------------

// Every settled request: who asked, for what, who decided, what they were
// given, and when.
//
// This is the tab somebody opens six months later to ask how a person came to be
// on a firewall, so it carries the whole record rather than a status word.
type HistoryFilter = "all" | "approved" | "denied" | "expired" | "cancelled";

function HistoryTab() {
  const [filter, setFilter] = useState<HistoryFilter>("all");

  const q = useQuery({
    queryKey: ["access-requests", "history", filter],
    queryFn: async () => {
      const qs = filter === "all" ? "?limit=200" : `?status=${filter}&limit=200`;
      return (await api.get<{ requests: AccessRequest[] }>(`/access-requests${qs}`)).data.requests ?? [];
    },
  });

  // Anything still pending belongs to the queue, not to the record of what
  // happened.
  const settled = useMemo(() => (q.data ?? []).filter((r) => r.status !== "pending"), [q.data]);

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorNote message={problemDetail(q.error, "Could not load the history")} />;

  return (
    <Panel
      title="Decision history"
      icon={IconAudit}
      subtitle="Every settled request — who asked, who decided, and what they were given"
      actions={
        <Select value={filter} onChange={(e) => setFilter(e.target.value as HistoryFilter)} className="w-auto">
          <option value="all">All outcomes</option>
          <option value="approved">Allowed</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
          <option value="cancelled">Withdrawn</option>
        </Select>
      }
      bodyClassName="p-0"
    >
      {settled.length === 0 ? (
        <div className="p-4">
          <EmptyState
            icon={IconAudit}
            title="Nothing decided yet"
            message="Once somebody requests access to a gated device and it is answered, the whole record appears here — including requests that expired unanswered."
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line bg-surface-2/50 text-left">
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">Who asked</th>
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">Device</th>
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">Outcome</th>
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">Allowed for</th>
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">Decided by</th>
                <th className="px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-faint">When</th>
              </tr>
            </thead>
            <tbody>
              {settled.map((r) => {
                const o = outcome(r);
                const last = (r.decisions ?? []).at(-1);
                return (
                  <tr key={r.id} className="border-b border-line/60 align-top last:border-0">
                    <td className="px-4 py-3">
                      <div className="text-fg">{r.requester}</div>
                      <div className="mt-0.5 max-w-xs text-xs text-muted">{r.reason}</div>
                      {r.is_emergency && (
                        <Badge tone="danger" className="mt-1">
                          Emergency{r.reviewed ? " · reviewed" : " · unreviewed"}
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-fg">{r.device}</td>
                    <td className="px-4 py-3">
                      <Badge tone={o.tone}>{o.label}</Badge>
                      {r.min_approvals > 1 && (
                        <div className="mt-1 text-2xs text-muted">
                          {r.approvals} of {r.min_approvals} approvals
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-muted">
                      {r.status === "approved" ? windowLabel(r) : <span className="text-faint">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-fg">
                        {last?.by ?? (
                          <span className="text-faint">{r.is_emergency ? "taken as emergency" : "nobody"}</span>
                        )}
                      </div>
                      {last?.note && <div className="mt-0.5 max-w-xs text-xs text-muted">“{last.note}”</div>}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-muted">
                      <div>{when(last?.decided_at ?? r.created_at)}</div>
                      <div className="text-faint">asked {when(r.created_at)}</div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

// ---- my requests ----------------------------------------------------------

function MineTab() {
  const qc = useQueryClient();
  const principal = useAuth((s) => s.principal);

  const q = useQuery({
    queryKey: ["access-requests", "mine", principal?.user_id],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>(`/access-requests?user_id=${principal?.user_id ?? ""}`)).data
        .requests ?? [],
    refetchInterval: 15_000,
  });

  const cancel = useMutation({
    mutationFn: async (id: string) => api.post(`/access-requests/${id}/cancel`),
    onSuccess: () => {
      toast.success("Request withdrawn");
      void qc.invalidateQueries({ queryKey: ["access-requests"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not withdraw the request")),
  });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorNote message={problemDetail(q.error, "Could not load your requests")} />;

  const list = q.data ?? [];
  if (list.length === 0) {
    return (
      <EmptyState
        icon={IconShield}
        title="You have not asked for anything"
        message="When you connect to a device that needs approval, the request shows up here so you can watch it."
      />
    );
  }

  return (
    <div className="space-y-3">
      {list.map((r) => (
        <RequestCard key={r.id} r={r}>
          {r.status === "pending" && (
            <Button variant="ghost" size="sm" disabled={cancel.isPending} onClick={() => cancel.mutate(r.id)}>
              Withdraw
            </Button>
          )}
        </RequestCard>
      ))}
    </div>
  );
}

// ---- emergency review -----------------------------------------------------

// Emergency access is granted first and reviewed afterwards. This queue is what
// keeps that a control rather than a hole: the access already happened, and
// somebody senior has to look at it and say so.
function EmergencyTab() {
  const qc = useQueryClient();
  const [note, setNote] = useState<Record<string, string>>({});

  const q = useQuery({
    queryKey: ["access-requests", "unreviewed"],
    queryFn: async () =>
      (await api.get<{ requests: AccessRequest[] }>("/access-requests?unreviewed=true")).data.requests ?? [],
  });

  const review = useMutation({
    mutationFn: async (id: string) => api.post(`/access-requests/${id}/review`, { note: note[id] ?? "" }),
    onSuccess: () => {
      toast.success("Signed off");
      void qc.invalidateQueries({ queryKey: ["access-requests"] });
    },
    onError: (e) => toast.error(problemDetail(e, "Could not sign off")),
  });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorNote message={problemDetail(q.error, "Could not load the review queue")} />;

  const list = q.data ?? [];
  if (list.length === 0) {
    return (
      <EmptyState
        icon={IconCheck}
        title="Nothing to review"
        message="Emergency access is taken without waiting for a decision and lands here to be signed off afterwards. Once signed off it stays in History."
      />
    );
  }

  return (
    <div className="space-y-3">
      {list.map((r) => (
        <RequestCard key={r.id} r={r}>
          <div className="flex w-full flex-col gap-2 sm:w-64">
            <Textarea
              rows={2}
              placeholder="What did you conclude?"
              value={note[r.id] ?? ""}
              onChange={(e) => setNote((n) => ({ ...n, [r.id]: e.target.value }))}
            />
            <Button variant="primary" size="sm" disabled={review.isPending} onClick={() => review.mutate(r.id)}>
              Sign off
            </Button>
          </div>
        </RequestCard>
      ))}
    </div>
  );
}
