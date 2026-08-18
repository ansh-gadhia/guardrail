import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { AccessRequest, ConnectResult, Device } from "@/lib/types";
import { REQUEST_WINDOWS } from "@/lib/types";
import { Button, Field, Modal, Select, Textarea, Badge, Hairline } from "@/components/ui";
import { IconAlert, IconClock, IconCheck } from "@/components/icons";
import { toast } from "@/components/Toast";

// Asking for access, and waiting for the answer.
//
// The waiting state is the hard part of an approval workflow. Two rules shape
// what follows:
//
//   1. Nothing auto-launches. When approval lands, the operator gets a button.
//      Opening a recorded, credential-injected session into a tab somebody
//      walked away from is exactly the unattended door the platform exists to
//      close.
//   2. The wait is never a bare spinner. It says who is being asked, how long
//      is left, and offers a way out — withdraw, or take emergency access.

export type ConnectOutcome =
  | { kind: "connected"; result: ConnectResult }
  | { kind: "pending"; request: AccessRequest }
  // The device is gated for this caller and nothing has been raised yet, because
  // we have not said why. Distinct from "pending": there is nothing to wait on,
  // the answer is "ask properly".
  | { kind: "needs_request" };

/** connectDevice performs a connect, distinguishing "in" from "you have to ask". */
export async function connectDevice(
  deviceID: string,
  body: { reason?: string; minutes?: number; emergency?: boolean } = {},
): Promise<ConnectOutcome> {
  const res = await api.post<ConnectResult & { status?: string; request?: AccessRequest }>(
    `/devices/${deviceID}/connect`,
    body,
  );
  // 202 means a request is now waiting on somebody. Not a failure — nothing went
  // wrong, the answer just is not in yet.
  if (res.status === 202 && res.data.request) {
    return { kind: "pending", request: res.data.request };
  }
  // 202 with no request: gated, and we have to ask. This is what the opening
  // probe below gets, and it is deliberately a separate outcome — falling
  // through to "connected" here handed the caller a body with no session_id and
  // the click did nothing at all.
  if (res.status === 202) {
    return { kind: "needs_request" };
  }
  return { kind: "connected", result: res.data as ConnectResult };
}

// RequestAccessModal collects the reason and the window, then waits.
export function RequestAccessModal({
  device,
  onClose,
  onConnected,
  // initialRequest opens straight into the waiting view. The probe returns a
  // request the caller already has in flight, and re-showing the form would ask
  // somebody to justify a request they have already made.
  initialRequest = null,
}: {
  device: Device;
  onClose: () => void;
  onConnected: (r: ConnectResult) => void;
  initialRequest?: AccessRequest | null;
}) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [pending, setPending] = useState<AccessRequest | null>(initialRequest);
  const [confirmEmergency, setConfirmEmergency] = useState(false);

  const ask = useMutation({
    mutationFn: async (emergency: boolean) =>
      connectDevice(device.id, { reason: reason.trim(), minutes, emergency }),
    onSuccess: (out) => {
      void qc.invalidateQueries({ queryKey: ["access-requests"] });
      if (out.kind === "connected") {
        onConnected(out.result);
        return;
      }
      if (out.kind === "needs_request") {
        // The server still wants a reason. Only reachable if the field was
        // emptied between validation and submit; say so rather than closing.
        toast.error("A reason is required to ask for access to this device");
        return;
      }
      setPending(out.request);
    },
    // problemDetail surfaces the server's sentence verbatim, which for a spent
    // quota names when the next one frees up. Do not shorten it to "denied":
    // during an incident the difference between four minutes and four days is
    // the whole decision.
    onError: (e) => toast.error(problemDetail(e, "Could not raise the request")),
  });

  if (pending) {
    return (
      <WaitingForApproval
        request={pending}
        device={device}
        onClose={onClose}
        onConnected={onConnected}
        onWithdrawn={onClose}
      />
    );
  }

  const canAsk = reason.trim().length >= 5 && !ask.isPending;

  return (
    <Modal onClose={onClose} title={`Request access to ${device.name}`} icon={IconClock}>
      <div className="space-y-4">
        <p className="text-sm text-muted">
          This device needs a decision from somebody who ranks above you before a session can start.
        </p>

        <Field
          label="Why do you need it?"
          hint="Required. Your approver decides on this, and it stays in the audit trail."
        >
          <Textarea
            rows={3}
            autoFocus
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Investigating the VPN tunnel flapping since 14:00 — ticket OPS-2214"
          />
        </Field>

        <Field label="For how long?" hint="Ask for what the task needs. Your approver can shorten it.">
          <Select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {REQUEST_WINDOWS.map((w) => (
              <option key={w.minutes} value={w.minutes}>
                {w.label}
              </option>
            ))}
          </Select>
        </Field>

        <Hairline />

        <div className="flex flex-wrap justify-between gap-2">
          {/* Emergency is deliberately present and deliberately quiet. Without a
              door, people route around approvals by sharing the break-glass
              credential — which is worse than having no approvals at all. */}
          <Button
            variant="ghost"
            disabled={!canAsk}
            onClick={() => setConfirmEmergency(true)}
            title="Connect now and have it reviewed afterwards"
          >
            <IconAlert size={15} /> Emergency access
          </Button>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!canAsk} loading={ask.isPending} onClick={() => ask.mutate(false)}>
              Request access
            </Button>
          </div>
        </div>

        {confirmEmergency && (
          <div className="rounded-lg border border-danger/40 bg-danger/5 p-3">
            <p className="text-sm font-medium text-fg">Take access now, without waiting?</p>
            <p className="mt-1 text-sm text-muted">
              You get in immediately. Every approver is notified at once, the session is flagged, and
              somebody senior has to sign it off afterwards. Use it when waiting would cause real harm.
            </p>
            {/* Said before the click, not only on refusal. Somebody finding out
                mid-incident that they used their last one a fortnight ago has
                been told too late to do anything with it. */}
            <p className="mt-1.5 text-xs text-faint">
              Emergency access is rationed. Taking one uses up part of your allowance for the period, and it
              does not reset when the session ends — if you are not sure this is an emergency, ask instead.
            </p>
            <div className="mt-3 flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setConfirmEmergency(false)}>
                Back
              </Button>
              <Button variant="danger" size="sm" loading={ask.isPending} onClick={() => ask.mutate(true)}>
                Take emergency access
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

// WaitingForApproval polls the request and hands over a Connect button when the
// answer arrives.
function WaitingForApproval({
  request,
  device,
  onClose,
  onConnected,
  onWithdrawn,
}: {
  request: AccessRequest;
  device: Device;
  onClose: () => void;
  onConnected: (r: ConnectResult) => void;
  onWithdrawn: () => void;
}) {
  const qc = useQueryClient();
  const [left, setLeft] = useState("");

  const q = useQuery({
    queryKey: ["access-request", request.id],
    queryFn: async () => (await api.get<AccessRequest>(`/access-requests/${request.id}`)).data,
    initialData: request,
    // Five seconds: somebody is sitting on this screen watching it. Slower feels
    // broken; faster buys nothing a human can perceive.
    refetchInterval: (query) => (query.state.data?.status === "pending" ? 5_000 : false),
  });

  const current = q.data ?? request;

  // A live countdown, because the number that matters is how long they have to
  // wait, and a static "expires at 14:32" makes the reader do the arithmetic.
  useEffect(() => {
    const tick = () => {
      const ms = new Date(current.expires_at).getTime() - Date.now();
      if (Number.isNaN(ms) || ms <= 0) {
        setLeft("expired");
        return;
      }
      const m = Math.floor(ms / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      setLeft(`${m}:${String(s).padStart(2, "0")}`);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [current.expires_at]);

  const redeem = useMutation({
    mutationFn: async () => connectDevice(device.id, {}),
    onSuccess: (out) => {
      // Three outcomes now, and they mean different things. "pending" is a
      // decision that has not landed yet; "needs_request" is an approval that
      // has been spent or has expired, leaving us back at the start. Reporting
      // both as "no longer usable" told somebody still waiting that their
      // request was dead.
      if (out.kind === "connected") onConnected(out.result);
      else if (out.kind === "pending") toast.error("Still waiting on a decision");
      else toast.error("That approval is no longer usable — ask again");
    },
    onError: (e) => toast.error(problemDetail(e, "Could not start the session")),
  });

  const withdraw = useMutation({
    mutationFn: async () => api.post(`/access-requests/${request.id}/cancel`),
    onSuccess: () => {
      toast.success("Request withdrawn");
      void qc.invalidateQueries({ queryKey: ["access-requests"] });
      onWithdrawn();
    },
    onError: (e) => toast.error(problemDetail(e, "Could not withdraw")),
  });

  // Same version-skew guard as the queue: never index into a list the server
  // might have sent as null.
  const decisions = current.decisions ?? [];
  const approved = current.status === "approved";
  const settled = current.status !== "pending";

  return (
    <Modal onClose={onClose} title={`Access to ${device.name}`} icon={approved ? IconCheck : IconClock}>
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Badge tone={approved ? "success" : current.status === "pending" ? "warn" : "danger"}>
            {current.status}
          </Badge>
          {current.min_approvals > 1 && (
            <Badge tone="neutral">
              {current.approvals} of {current.min_approvals} approvals
            </Badge>
          )}
          {current.escalated_level != null && <Badge tone="warn">Escalated</Badge>}
        </div>

        {current.status === "pending" && (
          <>
            <p className="text-sm text-fg">
              Waiting on somebody who ranks above you. You can leave this open, or close it — the
              request stays live either way and is listed under <b>Approvals → My requests</b>.
            </p>
            <div className="rounded-lg border border-line bg-surface-2 p-3">
              <div className="font-mono text-2xl tabular-nums text-fg">{left}</div>
              <p className="mt-1 text-xs text-muted">
                until it escalates to the next rank. If nobody answers after that, it expires.
              </p>
            </div>
          </>
        )}

        {approved && (
          <>
            <p className="text-sm text-fg">
              Approved
              {decisions.length > 0 && ` by ${decisions[decisions.length - 1].by}`}
              {current.granted_minutes != null && ` for ${current.granted_minutes} minutes`}.
            </p>
            {current.granted_minutes != null && current.granted_minutes < current.requested_minutes && (
              <p className="text-sm text-warn">
                Shortened from the {current.requested_minutes} minutes you asked for.
              </p>
            )}
            {/* Deliberately a button, not an auto-redirect. */}
            <Button variant="primary" block loading={redeem.isPending} onClick={() => redeem.mutate()}>
              Connect now
            </Button>
          </>
        )}

        {current.status === "denied" && (
          <p className="text-sm text-fg">
            Denied
            {decisions.length > 0 && ` by ${decisions[decisions.length - 1].by}`}.
            {decisions.at(-1)?.note && (
              <>
                {" "}
                <span className="text-muted">“{decisions.at(-1)?.note}”</span>
              </>
            )}
          </p>
        )}

        {(current.status === "expired" || current.status === "cancelled") && (
          <p className="text-sm text-muted">
            This request is {current.status}. Close this and try again if you still need access.
          </p>
        )}

        <div className="flex justify-end gap-2">
          {!settled && (
            <Button variant="ghost" loading={withdraw.isPending} onClick={() => withdraw.mutate()}>
              Withdraw
            </Button>
          )}
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
}
