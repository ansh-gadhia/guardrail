import { useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AuditRow } from "@/lib/types";
import { PageHero, ErrorNote, EmptyState, StatusBadge, Select, Button, Skeleton, Drawer } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { IconAudit, IconDownload, IconGlobe } from "@/components/icons";
import { toast } from "@/components/Toast";

// A stable key per row — the audit feed has no primary id, so we pair the row's
// index with its timestamp to keep React keys and selection stable across sorts.
type Row = AuditRow & { _k: string };

export function AuditPage() {
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);

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
      cell: (r) => <span className="whitespace-nowrap text-xs tabular-nums text-faint">{new Date(r.ts).toLocaleString()}</span>,
    },
    {
      key: "action",
      header: "Action",
      value: (r) => r.action,
      cell: (r) => <span className="font-mono text-xs text-fg">{r.action}</span>,
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
      value: (r) => (r.target_type ? `${r.target_type}:${r.target_id}` : ""),
      cell: (r) => (
        <span className="font-mono text-2xs text-faint">
          {r.target_type ? `${r.target_type}:${r.target_id.slice(0, 8)}` : "—"}
        </span>
      ),
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
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" icon={IconDownload} onClick={() => downloadReport("audit")}>
              Audit CSV
            </Button>
            <Button variant="ghost" size="sm" icon={IconDownload} onClick={() => downloadReport("access")}>
              Access CSV
            </Button>
          </div>
        }
      />

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
              </Select>
            </>
          }
        />
      )}

      {selected && <AuditDetailDrawer event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

/* ---- Event detail drawer ---------------------------------------------------
   Click any row to inspect the whole event: who, what, from where, on what, and
   the structured payload the action recorded (a device name, a session id,
   a failure cause…). This is what makes the log answer "what exactly happened". */
function AuditDetailDrawer({ event, onClose }: { event: Row; onClose: () => void }) {
  const dt = new Date(event.ts);
  const validDate = !Number.isNaN(dt.getTime());
  const detailEntries = Object.entries(event.detail ?? {});

  return (
    <Drawer title={event.action} subtitle={event.category || "event"} icon={IconAudit} onClose={onClose}>
      <div className="space-y-5">
        <div className="flex items-center gap-2">
          <StatusBadge value={event.result} />
          {validDate && <span className="text-xs text-muted">{timeAgo(dt)}</span>}
        </div>

        <dl className="space-y-3">
          <DRow label="When">
            <div className="text-sm text-fg">{validDate ? dt.toLocaleString() : event.ts}</div>
            {validDate && <div className="font-mono text-2xs text-faint">{dt.toISOString()}</div>}
          </DRow>
          <DRow label="Actor">{event.actor || "system"}</DRow>
          <DRow label="Action">
            <span className="font-mono text-xs text-fg">{event.action}</span>
          </DRow>
          <DRow label="Target">
            {event.target_type ? (
              <span className="break-all font-mono text-xs text-fg">
                {event.target_type}:{event.target_id}
              </span>
            ) : (
              "—"
            )}
          </DRow>
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

function DRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[6rem_1fr] gap-3">
      <dt className="pt-0.5 text-2xs font-semibold uppercase tracking-wider text-faint">{label}</dt>
      <dd className="min-w-0 text-sm text-fg">{children}</dd>
    </div>
  );
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
