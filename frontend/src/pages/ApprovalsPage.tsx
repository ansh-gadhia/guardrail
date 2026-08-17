import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { AccessGrant, AccessRequest, GrantScope } from "@/lib/types";
import { useAuth } from "@/store/auth";
import {
  PageHero, Panel, Spinner, ErrorNote, EmptyState, Badge, Button, Modal,
  Field, Select, Textarea, Tabs, Hairline,
} from "@/components/ui";
import { IconCheck, IconClock, IconShield, IconAlert, IconTrash } from "@/components/icons";
import { toast } from "@/components/Toast";
import { plausibleDate } from "@/lib/dates";

// Approvals.
//
// The queue is the screen an approver lives on, so it is built to be decided
// from rather than read: who, what, why, and how long — then two buttons. The
// reason is given the most room of anything on the row, because it is the only
// field that actually informs the decision.

type Tab = "queue" | "mine" | "grants" | "emergency";

export function ApprovalsPage() {
  const principal = useAuth((s) => s.principal);
  const canDecide = !!principal?.is_super_admin || !!principal?.permissions.includes("approval:decide");
  const canRead = canDecide || !!principal?.permissions.includes("approval:read");
  const [tab, setTab] = useState<Tab>(canDecide ? "queue" : "mine");

  const tabs = [
    ...(canDecide ? [{ id: "queue", label: "Awaiting decision", icon: IconClock }] : []),
    { id: "mine", label: "My requests", icon: IconShield },
    ...(canRead ? [{ id: "grants", label: "Standing access", icon: IconCheck }] : []),
    ...(canDecide ? [{ id: "emergency", label: "Emergency review", icon: IconAlert }] : []),
  ];

  return (
    <div>
      <PageHero
        icon={IconShield}
        eyebrow="Governance"
        title="Approvals"
        subtitle="Decide who may reach a gated device, and for how long"
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
      {tab === "mine" && <MineTab />}
      {tab === "grants" && <GrantsTab canRevoke={canDecide} />}
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

// countdown says how long is left in words. A pending request is a clock
// somebody is waiting on, and "expires 14:32" makes the reader do the maths.
function countdown(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return "";
  if (ms <= 0) return "expired";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}m left`;
  return `${Math.round(mins / 60)}h left`;
}

function windowLabel(r: AccessRequest): string {
  const m = r.granted_minutes ?? r.requested_minutes;
  const asked = r.requested_minutes;
  const label = m < 60 ? `${m} min` : `${Math.round((m / 60) * 10) / 10} h`;
  // Name the shortening explicitly. An operator who asked for four hours and
  // got one needs to know before they start, not when the session ends.
  if (r.granted_minutes != null && r.granted_minutes < asked) {
    return `${label} (asked ${asked < 60 ? `${asked} min` : `${asked / 60} h`})`;
  }
  return label;
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
            <span>Asked {plausibleDate(r.created_at)?.toLocaleString() ?? "—"}</span>
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
    queryFn: async () => (await api.get<{ requests: AccessRequest[] }>("/access-requests?pending=true")).data.requests ?? [],
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
        message="Requests to reach approval-gated devices appear here. You can only decide requests from people who rank below you."
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
// "Allow all time" is deliberately styled as the heavier choice and labelled
// with what it actually does: it is not an answer to this request, it is a
// standing grant that will still be there in six months.
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

        <Field
          label="Grant for"
          hint="You can shorten what they asked for, but not extend it."
        >
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

        <Field label="Note" hint="Recorded against the decision and visible in the audit trail.">
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
          {/* Say what the heavier button costs, next to the button. */}
          <p className="px-1 text-xs text-muted">
            Standing access never asks again. It appears under <b>Standing access</b>, where it can be
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

// ---- my requests ----------------------------------------------------------

function MineTab() {
  const qc = useQueryClient();
  const principal = useAuth((s) => s.principal);

  const q = useQuery({
    queryKey: ["access-requests", "mine"],
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

// ---- standing grants ------------------------------------------------------

function GrantsTab({ canRevoke }: { canRevoke: boolean }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState<AccessGrant | null>(null);

  const q = useQuery({
    queryKey: ["access-grants"],
    queryFn: async () => (await api.get<{ grants: AccessGrant[] }>("/access-grants?live=true")).data.grants ?? [],
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

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorNote message={problemDetail(q.error, "Could not load standing access")} />;

  const list = q.data ?? [];

  return (
    <div className="space-y-4">
      <Panel
        title="Standing access"
        subtitle="Everyone who can reach a gated device without asking. This is the list that answers “who can get in without a decision?”"
      >
        {list.length === 0 ? (
          <p className="text-sm text-muted">
            Nobody holds standing access. Every gated connect is decided one at a time.
          </p>
        ) : (
          <div className="divide-y divide-line">
            {list.map((g) => (
              <div key={g.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-fg">
                    {g.user} <span className="text-muted">on</span> {g.device}
                  </div>
                  <div className="mt-0.5 text-xs text-muted">
                    Granted by {g.granted_by || "—"} · {plausibleDate(g.created_at)?.toLocaleDateString() ?? "—"}
                    {g.expires_at ? ` · until ${plausibleDate(g.expires_at)?.toLocaleDateString() ?? "?"}` : " · no expiry"}
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

      {confirm && (
        <Modal onClose={() => setConfirm(null)} title="Revoke standing access?">
          <p className="text-sm text-fg">
            {confirm.user} will have to ask for approval again to reach {confirm.device}.
          </p>
          <p className="mt-2 text-sm text-muted">
            Any session they currently hold on this device ends immediately — revoking that left the
            current session running would mean “allow once” quietly meant “allow for the next eight hours”.
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
        message="Emergency access is taken without waiting for a decision, and lands here to be signed off afterwards."
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
