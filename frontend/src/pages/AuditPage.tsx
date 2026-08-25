import { useMemo, useState, type ComponentType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { plausibleDate } from "@/lib/dates";
import type { AuditRow } from "@/lib/types";
import { PageHero, ErrorNote, EmptyState, StatusBadge, Select, Button, Skeleton, Drawer, cn } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import {
  IconAudit,
  IconDownload,
  IconGlobe,
  IconDevices,
  IconUsers,
  IconKey,
  IconSessions,
  IconClipboard,
  IconCheck,
  IconShield,
  IconFolder,
  IconFilm,
} from "@/components/icons";
import { toast } from "@/components/Toast";
import { ChainVerdict, VerifyChainButton, useChainVerification } from "@/components/AuditIntegrity";

// A stable key per row — the audit feed has no primary id, so we pair the row's
// index with its timestamp to keep React keys and selection stable across sorts.
type Row = AuditRow & { _k: string };

/* ---- Outcome ----------------------------------------------------------------
   The log is a record of decisions, so the outcome is the one thing a reviewer
   scans for. It used to live only in a badge at the far right — the last thing
   read on a row, a hundred rows down. Every row now also carries a rail on its
   leading edge tinted by outcome, so refusals and failures form a visible rhythm
   down the left of the table before a single word is read.

   Deliberately per-row, not a continuous spine: the table sorts, and a rail that
   implied the rows were still in chain order would become a lie the moment
   somebody clicked a column header. */
const RAIL: Record<string, string> = {
  success: "border-l-2 border-l-success/40",
  pending: "border-l-2 border-l-warn/70",
  denied: "border-l-2 border-l-danger/70",
  failure: "border-l-2 border-l-danger/70",
};
const NODE: Record<string, string> = {
  success: "bg-success/55",
  pending: "bg-warn",
  denied: "bg-danger",
  failure: "bg-danger",
};

export function AuditPage() {
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  // Verification lives here as well as on the organization page, because this is
  // where somebody is actually reading the log — and "can I trust what I am
  // looking at" is a question you have while looking at it.
  const { report, verify } = useChainVerification();

  const { data, isLoading, isError } = useQuery<AuditRow[]>({
    queryKey: ["audit", action, result],
    queryFn: async () =>
      (await api.get<{ data: AuditRow[] }>("/audit", { params: { action, result, limit: 100 } })).data.data,
  });

  const rows = useMemo<Row[]>(() => (data ?? []).map((r, i) => ({ ...r, _k: `${i}-${r.ts}` })), [data]);

  const downloadReport = async (type: "audit" | "access") => {
    try {
      const res = await api.post("/reports", { type, format: "csv" }, { responseType: "blob" });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `guardrail-${type}-report.csv`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`${type === "audit" ? "Audit" : "Access"} report downloaded`);
    } catch {
      toast.error("Report export failed");
    }
  };

  const columns: Column<Row>[] = [
    {
      key: "ts",
      header: "Time",
      value: (r) => r.ts,
      cell: (r) => (
        <span className="flex items-center gap-2.5">
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", NODE[r.result] ?? "bg-line-strong")} />
          <span className="whitespace-nowrap text-xs tabular-nums text-faint">{fmtAbs(r.ts)}</span>
        </span>
      ),
    },
    {
      key: "action",
      header: "Action",
      value: (r) => r.action,
      cell: (r) => <ActionName action={r.action} />,
    },
    {
      key: "category",
      header: "Category",
      value: (r) => r.category,
      cell: (r) => <span className="text-xs text-muted">{r.category || "—"}</span>,
      defaultHidden: true,
    },
    {
      key: "actor",
      header: "Actor",
      value: (r) => r.actor || "system",
      cell: (r) => <span className="text-sm text-fg">{r.actor || "system"}</span>,
    },
    {
      key: "target",
      header: "Target",
      value: (r) => targetSortValue(r),
      cell: (r) => <TargetCell row={r} />,
    },
    {
      key: "ip",
      header: "Source IP",
      value: (r) => r.ip,
      cell: (r) =>
        r.ip ? (
          <span className="inline-flex items-center gap-1.5">
            <IconGlobe size={13} className="text-faint" />
            <span className="rounded-md border border-line bg-surface-2/60 px-1.5 py-0.5 font-mono text-2xs text-fg">
              {r.ip}
            </span>
          </span>
        ) : (
          <span className="text-2xs text-faint">—</span>
        ),
    },
    {
      key: "result",
      header: "Result",
      value: (r) => r.result,
      cell: (r) => <StatusBadge value={r.result} />,
      align: "right",
    },
  ];

  return (
    <div>
      <PageHero
        icon={IconAudit}
        eyebrow="Governance"
        title="Audit Log"
        subtitle="Tamper-evident, hash-chained record of every privileged action."
        actions={
          <div className="flex flex-wrap gap-2">
            <VerifyChainButton pending={verify.isPending} onRun={() => verify.mutate()} />
            <Button variant="ghost" size="sm" icon={IconDownload} onClick={() => downloadReport("audit")}>
              Audit CSV
            </Button>
            <Button variant="ghost" size="sm" icon={IconDownload} onClick={() => downloadReport("access")}>
              Access CSV
            </Button>
          </div>
        }
      />

      {report && (
        <div className="mb-4">
          <ChainVerdict report={report} />
        </div>
      )}

      {isLoading && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <Skeleton className="h-9 flex-1" />
            <Skeleton className="h-9 w-40" />
          </div>
          <Skeleton className="h-[28rem]" />
        </div>
      )}
      {isError && <ErrorNote message="Failed to load audit log" />}

      {data && data.length === 0 && (action || result) && (
        <EmptyState icon={IconAudit} title="No events" message="No audit events match your filters." />
      )}
      {data && data.length === 0 && !action && !result && (
        <EmptyState icon={IconAudit} title="No events yet" message="Privileged actions will appear here as they happen." />
      )}

      {data && data.length > 0 && (
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => r._k}
          rowClassName={(r) => RAIL[r.result] ?? "border-l-2 border-l-transparent"}
          searchPlaceholder="Search events…"
          pageSize={15}
          exportName="guardrail-audit"
          emptyMessage="No events match your search."
          onRowClick={setSelected}
          toolbar={
            <>
              <input
                className="input max-w-[13rem]"
                placeholder="Action (e.g. auth.login)"
                value={action}
                onChange={(e) => setAction(e.target.value)}
              />
              <Select className="max-w-[10rem]" value={result} onChange={(e) => setResult(e.target.value)}>
                <option value="">All results</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
                <option value="pending">Pending</option>
              </Select>
            </>
          }
        />
      )}

      {selected && <AuditDetailDrawer event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

/* ---- Action name ------------------------------------------------------------
   Actions are dotted keys — `approval.requested`, `auth.login`. Dimming the
   namespace lets the eye land on the verb, which is the part that differs
   between two adjacent rows in the same namespace. */
function ActionName({ action }: { action: string }) {
  const dot = action.indexOf(".");
  if (dot < 0) return <span className="font-mono text-xs text-fg">{action}</span>;
  return (
    <span className="font-mono text-xs">
      <span className="text-faint">{action.slice(0, dot + 1)}</span>
      <span className="text-fg">{action.slice(dot + 1)}</span>
    </span>
  );
}

/* ---- Target -----------------------------------------------------------------
   The target used to render as `device:baaf24df` — a type and eight hex
   characters, which tells a reviewer nothing without going and looking it up
   somewhere else. The server now resolves it to the name that same reviewer
   would recognise, and this renders the name with a glyph for its kind.

   Four states, all of them real, none of them an unexplained blank:
     resolved   the name, with a kind glyph
     purged     the subject is gone — the short id in mono, so it can still be
                matched against a backup or an export
     self       the target IS the actor (signing in, changing your own password).
                Saying "self" is information; an em-dash reads as missing data,
                which is what made the column look broken.
     none       the action genuinely acts on no single record. */
const TARGET_ICON: Record<string, ComponentType<{ size?: number; className?: string }>> = {
  device: IconDevices,
  user: IconUsers,
  credential: IconKey,
  session: IconSessions,
  role: IconShield,
  group: IconFolder,
};

function TargetCell({ row }: { row: Row }) {
  const { target_type: type, target_id: id, target_label: label } = row;

  if (!type || !id) return <span className="text-2xs text-faint">—</span>;
  if (isSelf(row)) return <span className="text-xs italic text-faint">self</span>;

  const Icon = TARGET_ICON[type];
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      {Icon && <Icon size={13} className="shrink-0 text-faint" />}
      {label ? (
        <span className="truncate text-sm text-fg">{label}</span>
      ) : (
        <span className="truncate font-mono text-2xs text-faint" title={`${type} ${id}`}>
          {id.slice(0, 8)}
        </span>
      )}
    </span>
  );
}

/** A self-directed action: the thing acted on is the account doing the acting. */
function isSelf(row: AuditRow): boolean {
  return row.target_type === "user" && !!row.actor && row.target_label === row.actor;
}

function targetSortValue(row: Row): string {
  if (isSelf(row)) return "self";
  return row.target_label || (row.target_type ? `${row.target_type}:${row.target_id}` : "");
}

/* ---- Event detail drawer ---------------------------------------------------
   Click any row to inspect the whole event: who, what, from where, on what, and
   the structured payload the action recorded (a device name, a session id,
   a failure cause…). This is what makes the log answer "what exactly happened". */
function AuditDetailDrawer({ event, onClose }: { event: Row; onClose: () => void }) {
  const dt = plausibleDate(event.ts);
  const detailEntries = Object.entries(event.detail ?? {});
  const TargetIcon = TARGET_ICON[event.target_type];

  return (
    <Drawer title={event.action} subtitle={event.category || "event"} icon={IconAudit} onClose={onClose} width="max-w-lg">
      <div className="space-y-5">
        <div className="flex items-center gap-2">
          <StatusBadge value={event.result} />
          {dt && <span className="text-xs text-muted">{timeAgo(dt)}</span>}
        </div>

        <dl className="space-y-3">
          <DRow label="When">
            <div className="text-sm text-fg">{dt ? dt.toLocaleString() : "unknown"}</div>
            {dt && <div className="font-mono text-2xs text-faint">{dt.toISOString()}</div>}
          </DRow>
          <DRow label="Actor">{event.actor || "system"}</DRow>
          <DRow label="Action">
            <span className="font-mono text-xs text-fg">{event.action}</span>
          </DRow>
          <DRow label="Target">
            {!event.target_type || !event.target_id ? (
              <span className="text-xs text-faint">
                This action acts on no single record, so it has no target.
              </span>
            ) : (
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5">
                  {TargetIcon && <TargetIcon size={14} className="shrink-0 text-faint" />}
                  <span className="min-w-0 truncate text-sm text-fg">
                    {event.target_label || <span className="text-faint">no longer exists</span>}
                  </span>
                  {isSelf(event) && <span className="shrink-0 text-2xs italic text-faint">· the actor's own account</span>}
                </div>
                <CopyableID label={event.target_type} value={event.target_id} />
              </div>
            )}
          </DRow>
          {event.session_id && (
            <DRow label="Session">
              {/* The recording, the timeline and the authorization behind this
                  entry are all one place. Without this the reader had the id and
                  a different page to go and search on. */}
              <Link
                to={`/recordings?session=${event.session_id}`}
                className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline"
              >
                <IconFilm size={14} />
                Open this session
              </Link>
              <div className="mt-1">
                <CopyableID label="session" value={event.session_id} />
              </div>
            </DRow>
          )}
          <DRow label="Source IP">
            <span className="font-mono text-xs text-fg">{event.ip || "—"}</span>
          </DRow>
          <DRow label="Client">
            <span className="break-all font-mono text-2xs text-muted">{event.user_agent || "—"}</span>
          </DRow>
        </dl>

        {detailEntries.length > 0 && (
          <div>
            <div className="mb-2 text-2xs font-semibold uppercase tracking-wider text-faint">Details</div>
            <div className="divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface-2/40">
              {detailEntries.map(([k, v]) => (
                <div key={k} className="flex gap-3 px-3 py-2 text-xs">
                  <span className="w-28 shrink-0 font-mono text-faint">{k}</span>
                  <span className="min-w-0 flex-1 break-all font-mono text-fg">
                    {typeof v === "string" ? v : JSON.stringify(v)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <p className="border-t border-line pt-3 text-2xs text-faint">
          Times shown in your local timezone. Audit events are append-only and hash-chained — they cannot be edited or deleted.
        </p>
      </div>
    </Drawer>
  );
}

/* The id is what you paste into a support ticket or another query, so it is kept
   — but demoted below the name, and made copyable, because reading 36 hex
   characters off a screen is not something anybody should be asked to do. */
function CopyableID({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        });
      }}
      className="group inline-flex max-w-full items-center gap-1.5 rounded-md border border-line bg-surface-2/50 px-1.5 py-0.5 text-left transition hover:border-line-strong"
      title="Copy id"
    >
      <span className="shrink-0 text-2xs uppercase tracking-wider text-faint">{label}</span>
      <span className="truncate font-mono text-2xs text-muted">{value}</span>
      {copied ? (
        <IconCheck size={11} className="shrink-0 text-success" />
      ) : (
        <IconClipboard size={11} className="shrink-0 text-faint opacity-0 transition-opacity group-hover:opacity-100" />
      )}
    </button>
  );
}

function DRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[6rem_1fr] gap-3">
      <dt className="pt-0.5 text-2xs font-semibold uppercase tracking-wider text-faint">{label}</dt>
      <dd className="min-w-0 text-sm text-fg">{children}</dd>
    </div>
  );
}

function fmtAbs(iso?: string): string {
  const d = plausibleDate(iso);
  return d ? d.toLocaleString() : "—";
}

function timeAgo(dt: Date): string {
  const s = Math.round((Date.now() - dt.getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
