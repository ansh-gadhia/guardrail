import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import { absLocal } from "@/lib/dates";
import type { ChainReport } from "@/lib/types";
import { toast } from "@/components/Toast";
import { Panel, Button, Skeleton, cn } from "@/components/ui";
import { IconLink, IconRefresh, IconCheck, IconAlert } from "@/components/icons";

/* ---------------------------------------------------------------------------
   Every audit entry is hashed together with the one before it, which is what
   makes the log tamper-EVIDENT rather than merely append-only. The chain was
   written from the first release and never read: a claim nobody could check is
   not much better than no claim. This walks it.
--------------------------------------------------------------------------- */

/** Runs a verification and hands back the report plus the pending flag. */
export function useChainVerification() {
  const [report, setReport] = useState<ChainReport | null>(null);
  const verify = useMutation({
    mutationFn: async () => (await api.post<ChainReport>("/audit/verify", {})).data,
    onSuccess: (r) => {
      setReport(r);
      if (r.ok) toast.success(`Chain intact across ${r.checked.toLocaleString()} entries`);
      else toast.error("The audit chain does not verify");
    },
    onError: (e) => toast.error(problemDetail(e, "The audit log could not be verified.")),
  });
  return { report, verify };
}

export function VerifyChainButton({
  pending,
  onRun,
}: {
  pending: boolean;
  onRun: () => void;
}) {
  return (
    <Button variant="ghost" size="sm" disabled={pending} onClick={onRun}>
      <IconRefresh size={14} className={cn(pending && "animate-spin")} />
      {pending ? "Checking…" : "Verify integrity"}
    </Button>
  );
}

/** The result, rendered the same way wherever it is shown. */
export function ChainVerdict({ report }: { report: ChainReport }) {
  return (
    <div
      className={cn(
        "rounded-xl border px-4 py-3",
        report.ok ? "border-success/30 bg-success/10" : "border-danger/35 bg-danger/10",
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cn(
            "grid h-7 w-7 shrink-0 place-items-center rounded-lg",
            report.ok ? "bg-success/15 text-success" : "bg-danger/15 text-danger",
          )}
        >
          {report.ok ? <IconCheck size={15} /> : <IconAlert size={15} />}
        </span>
        <div className="min-w-0">
          <div className="font-display text-sm font-semibold text-fg">
            {report.ok
              ? report.checked === 0
                ? "Nothing to verify yet"
                : "The chain verifies"
              : "The chain is broken"}
          </div>
          <div className="text-2xs text-muted">
            {report.checked.toLocaleString()} {report.checked === 1 ? "entry" : "entries"} checked
            {report.from && report.to ? ` · ${absLocal(report.from)} → ${absLocal(report.to)}` : ""}
          </div>
        </div>
      </div>
      {!!report.unverifiable && (
        // Neither proved nor accused. These were written before the hash covered
        // values the database gives back unchanged, so they cannot be recomputed
        // — and the log is append-only, so there is nothing to rewrite them with.
        <p className="mt-2 border-t border-line pt-2 text-2xs text-muted">
          {report.unverifiable.toLocaleString()} earlier{" "}
          {report.unverifiable === 1 ? "entry predates" : "entries predate"} integrity verification and could not be
          recomputed. They are still linked into the chain, so everything after them is covered.
        </p>
      )}
      {report.ok && report.truncated && (
        // Says what it proved and what it did not. "Verified" over a slice of the
        // log, presented as if it covered all of it, is the kind of reassurance
        // that is worse than none.
        <p className="mt-2 border-t border-success/20 pt-2 text-2xs text-muted">
          This pass stopped at its row limit, so it proves the entries it read and says nothing about any beyond them.
        </p>
      )}
      {!report.ok && (
        <div className="mt-3 space-y-1 border-t border-danger/20 pt-3 text-xs">
          <p className="text-fg">{report.reason || "An entry does not match the hash recorded for it."}</p>
          {report.broken_at && (
            <p className="text-muted">
              First break at entry <span className="font-mono text-2xs text-fg">{report.broken_at}</span>
              {report.broken_at_ts ? ` (${absLocal(report.broken_at_ts)})` : ""}.
            </p>
          )}
          <p className="text-muted">
            Everything before that point still verifies. Treat entries from there on as unproven, and preserve the
            database for investigation.
          </p>
        </div>
      )}
    </div>
  );
}

/** The full panel, for the organization policy page. */
export function IntegrityPanel() {
  const { report, verify } = useChainVerification();
  return (
    <Panel
      icon={IconLink}
      title="Audit log integrity"
      subtitle="Every entry is hashed together with the one before it. Walking that chain proves nothing has been altered or removed."
      actions={<VerifyChainButton pending={verify.isPending} onRun={() => verify.mutate()} />}
    >
      {!report && !verify.isPending && (
        <p className="text-xs text-muted">
          Nothing has been checked in this session. Run a verification to confirm the log is intact.
        </p>
      )}
      {verify.isPending && <Skeleton className="h-16 rounded-lg" />}
      {report && <ChainVerdict report={report} />}
    </Panel>
  );
}
