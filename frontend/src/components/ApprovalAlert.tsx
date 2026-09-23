import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { AccessRequest } from "@/lib/types";
import { DecideModal } from "@/pages/ApprovalsPage";
import { IconCheck, IconAlert } from "@/components/icons";

/* ApprovalAlert pops up the moment somebody asks this person for access.

   An approval system whose only signal is a badge on a page you have no reason
   to open fails quietly: the requester waits, concludes the system is slow, and
   nobody knew they had been asked. So a newly-arrived request comes to the
   approver — in whatever page they are on — and "Review" opens the same decide
   dialog the Approvals page uses, in place, so deciding does not mean leaving
   what they were doing.

   Only NEW requests pop up. The backlog that is already waiting when the console
   loads is the badge's job; popping a stack of cards for requests somebody has
   already seen and chosen not to act on yet would be nagging, and nagging is how
   people learn to dismiss without reading. */
export function ApprovalAlert({ pending }: { pending: AccessRequest[] | undefined }) {
  const qc = useQueryClient();
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<AccessRequest[]>([]);
  const [deciding, setDeciding] = useState<AccessRequest | null>(null);

  useEffect(() => {
    if (!pending) return;
    // First load establishes what already existed; nothing pops for it.
    if (seen.current === null) {
      seen.current = new Set(pending.map((r) => r.id));
      return;
    }
    const arrived = pending.filter((r) => !seen.current!.has(r.id));
    pending.forEach((r) => seen.current!.add(r.id));
    // Drop cards for requests that were decided elsewhere — by another approver,
    // or in another tab — so a card never offers to decide something settled.
    const stillPending = new Set(pending.map((r) => r.id));
    setFresh((cur) => [...cur.filter((r) => stillPending.has(r.id)), ...arrived]);
  }, [pending]);

  if (fresh.length === 0 && !deciding) return null;

  return (
    <>
      <div className="fixed bottom-4 right-4 z-50 flex w-[22rem] max-w-[calc(100vw-2rem)] flex-col gap-2">
        {fresh.slice(0, 3).map((r) => (
          <div
            key={r.id}
            role="alert"
            className="animate-in rounded-xl border border-warn/40 bg-surface-1 p-3 shadow-lg ring-1 ring-warn/20"
          >
            <div className="flex items-start gap-2.5">
              <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-warn/15 text-warn">
                {r.is_emergency ? <IconAlert size={15} /> : <IconCheck size={15} />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-fg">
                  {r.is_emergency ? "Emergency access taken" : "Access requested"}
                </div>
                <div className="truncate text-xs text-muted">
                  <span className="font-medium text-fg">{r.requester}</span> → {r.device}
                </div>
                {r.reason && <div className="mt-1 line-clamp-2 text-xs text-faint">“{r.reason}”</div>}
              </div>
            </div>
            <div className="mt-2.5 flex justify-end gap-2">
              <button
                className="btn-ghost text-xs"
                onClick={() => setFresh((cur) => cur.filter((x) => x.id !== r.id))}
              >
                Later
              </button>
              <button
                className="btn-primary text-xs"
                onClick={() => {
                  setDeciding(r);
                  setFresh((cur) => cur.filter((x) => x.id !== r.id));
                }}
              >
                Review
              </button>
            </div>
          </div>
        ))}
        {fresh.length > 3 && (
          <div className="rounded-lg bg-surface-2 px-3 py-1.5 text-center text-xs text-muted">
            and {fresh.length - 3} more waiting — see Approvals
          </div>
        )}
      </div>
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
    </>
  );
}
