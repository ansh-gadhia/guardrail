import { useEffect, useMemo, useState, type ComponentType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useDebounced } from "@/hooks/useDebounced";
import { api } from "@/lib/api";
import { plausibleDate } from "@/lib/dates";
import type { AuditRow, Paged } from "@/lib/types";
import { PageHero, ErrorNote, EmptyState, StatusBadge, Select, Button, Skeleton, Drawer, cn } from "@/components/ui";
import { DataTable, type Column, type SortDir } from "@/components/DataTable";
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
  IconLock,
  IconSettings,
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

/* ---- Groups -----------------------------------------------------------------
   The families the log is filtered by. The server decides which family an event
   belongs to (analytics/describe.go) and filters by the same key, so choosing
   one here can never hide an event labelled with it. */
const AUDIT_GROUPS: { key: string; label: string; icon: ComponentType<{ size?: number; className?: string }> }[] = [
  { key: "signin", label: "Sign-in", icon: IconLock },
  { key: "access", label: "Access requests", icon: IconCheck },
  { key: "sessions", label: "Sessions", icon: IconSessions },
  { key: "recordings", label: "Recordings", icon: IconFilm },
  { key: "devices", label: "Devices & credentials", icon: IconDevices },
  { key: "people", label: "People & teams", icon: IconUsers },
  { key: "settings", label: "Settings", icon: IconSettings },
  { key: "system", label: "System", icon: IconAudit },
];
const GROUP = Object.fromEntries(AUDIT_GROUPS.map((g) => [g.key, g]));

export function AuditPage() {
  const [group, setGroup] = useState("");
  const [result, setResult] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  // Verification lives here as well as on the organization page, because this is
  // where somebody is actually reading the log — and "can I trust what I am
  // looking at" is a question you have while looking at it.
  const { report, verify } = useChainVerification();

  // The server pages the log, so the last page is the first event ever
  // recorded — it used to stop at whatever the newest 200 happened to be.
  // Search runs there too, across the whole log, by person, machine, IP or
  // event code.
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [query, setQuery] = useState("");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const search = useDebounced(query.trim(), 300);
  useEffect(() => setPage(0), [search, group, result, sortDir, pageSize]);

  const listParams = useMemo(
    () => ({ group, result, q: search, dir: sortDir, limit: pageSize, offset: page * pageSize }),
    [group, result, search, sortDir, pageSize, page],
  );
  const { data: pageData, isLoading, isError, isFetching } = useQuery<Paged<AuditRow>>({
    queryKey: ["audit", "page", listParams],
    queryFn: async () => (await api.get<Paged<AuditRow>>("/audit", { params: listParams })).data,
    placeholderData: keepPreviousData,
  });
  const data = pageData?.data;
  const total = pageData?.total ?? 0;
  const filtered = !!(group || result || search);

  const rows = useMemo<Row[]>(
    () => (data ?? []).map((r, i) => ({ ...r, _k: `${page}-${i}-${r.ts}` })),
    [data, page],
  );

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
      cell: (r) => {
        const dt = plausibleDate(r.ts);
        return (
          <span
            className="flex items-start gap-2.5"
            // Events written before July 2026 by an early build carry no time at
            // all; they are real, and chained, so they are shown as they are.
            title={dt ? dt.toLocaleString() : "This event was stored without a time by an early version of GuardRail."}
          >
            <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", NODE[r.result] ?? "bg-line-strong")} />
            <span className="leading-tight">
              {dt ? (
                <>
                  <span className="block whitespace-nowrap text-xs tabular-nums text-fg">{fmtWhen(dt)}</span>
                  <span className="block whitespace-nowrap text-2xs text-faint">{timeAgo(dt)}</span>
                </>
              ) : (
                <span className="block whitespace-nowrap text-xs italic text-faint">Not recorded</span>
              )}
            </span>
          </span>
        );
      },
    },
    {
      key: "event",
      sortable: false,
      header: "Event",
      // Searchable by what it says, not by its code.
      value: (r) => `${r.title ?? r.action} ${r.note ?? ""}`,
      cell: (r) => <EventCell row={r} />,
    },
    {
      key: "actor",
      sortable: false,
      header: "Who",
      value: (r) => r.actor || "GuardRail",
      cell: (r) => <ActorCell actor={r.actor} />,
    },
    {
      key: "target",
      sortable: false,
      header: "On",
      value: (r) => targetSortValue(r),
      cell: (r) => <TargetCell row={r} />,
    },
    {
      key: "ip",
      sortable: false,
      header: "Source IP",
      value: (r) => r.ip,
      cell: (r) =>
        r.ip ? (
          <span className="inline-flex items-center gap-1.5">
            <IconGlobe size={13} className="text-faint" />
            <span className="font-mono text-2xs text-muted">{r.ip}</span>
          </span>
        ) : (
          <span className="text-2xs text-faint">—</span>
        ),
    },
    {
      key: "action",
      sortable: false,
      header: "Event code",
      value: (r) => r.action,
      cell: (r) => <ActionName action={r.action} />,
      defaultHidden: true,
    },
    {
      key: "result",
      sortable: false,
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

      {data && total === 0 && !filtered && (
        <EmptyState icon={IconAudit} title="No events yet" message="Privileged actions will appear here as they happen." />
      )}

      {data && (total > 0 || filtered) && (
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => r._k}
          rowClassName={(r) => RAIL[r.result] ?? "border-l-2 border-l-transparent"}
          searchPlaceholder="Search by person, machine, IP or event code…"
          exportName="guardrail-audit"
          emptyMessage={search ? `No events match “${search}”.` : "No audit events match these filters."}
          onRowClick={setSelected}
          server={{
            total,
            page,
            onPageChange: setPage,
            pageSize,
            onPageSizeChange: setPageSize,
            query,
            onQueryChange: setQuery,
            sortKey: "ts",
            sortDir,
            onSortChange: (_k, d) => setSortDir(d),
            loading: isFetching,
            // The whole filtered log, not the page on screen; capped so one click
            // cannot ask for an unbounded response.
            fetchAll: async () => {
              const { data } = await api.get<Paged<AuditRow>>("/audit", {
                params: { ...listParams, limit: 5000, offset: 0 },
              });
              return data.data.map((r, i) => ({ ...r, _k: `all-${i}` }));
            },
          }}
          toolbar={
            <>
              <Select className="max-w-[13rem]" value={group} onChange={(e) => setGroup(e.target.value)}>
                <option value="">All activity</option>
                {AUDIT_GROUPS.map((g) => (
                  <option key={g.key} value={g.key}>
                    {g.label}
                  </option>
                ))}
              </Select>
              <Select className="max-w-[10rem]" value={result} onChange={(e) => setResult(e.target.value)}>
                <option value="">Any result</option>
                <option value="success">Succeeded</option>
                <option value="failure">Failed</option>
                <option value="denied">Refused</option>
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

/* ---- Event ----------------------------------------------------------------------
   What happened, as the server words it, with the one fact worth reading under
   it. The tile names the family at a glance; it stays quiet for the ordinary
   and takes the outcome's colour when something failed, was refused, or is
   waiting — so the rows that need a second look are the ones that stand out. */
const TILE: Record<string, string> = {
  failure: "bg-danger/10 text-danger ring-danger/20",
  denied: "bg-danger/10 text-danger ring-danger/20",
  pending: "bg-warn/10 text-warn ring-warn/25",
};

function EventCell({ row }: { row: Row }) {
  const Icon = GROUP[row.group ?? ""]?.icon ?? IconAudit;
  return (
    <span className="flex min-w-0 items-start gap-2.5">
      <span
        className={cn(
          "mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg ring-1 ring-inset",
          TILE[row.result] ?? "bg-surface-2 text-muted ring-line",
        )}
      >
        <Icon size={14} />
      </span>
      <span className="min-w-0 max-w-[18rem] leading-tight">
        <span className="block truncate text-sm font-medium text-fg">{row.title || row.action}</span>
        {row.note && (
          <span className="mt-0.5 block truncate text-xs text-muted" title={row.note}>
            {row.note}
          </span>
        )}
      </span>
    </span>
  );
}

/* Who did it. Things GuardRail did by itself — purging a recording on schedule,
   injecting a credential — are GuardRail's, and say so, rather than "system". */
function ActorCell({ actor }: { actor: string }) {
  if (!actor) {
    return (
      <span className="flex items-center gap-2">
        <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-accent-soft text-accent">
          <IconShield size={12} />
        </span>
        <span className="text-sm text-muted">GuardRail</span>
      </span>
    );
  }
  return (
    <span className="flex min-w-0 max-w-[12rem] items-center gap-2">
      <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-surface-2 text-2xs font-semibold uppercase text-muted ring-1 ring-inset ring-line">
        {actor.slice(0, 2)}
      </span>
      <span className="truncate text-sm text-fg" title={actor}>
        {actor}
      </span>
    </span>
  );
}

/* ---- Target -----------------------------------------------------------------
   What the event was done to, by name, with what kind of thing it is under it —
   "MyUbuntuServerDLP / Device". Four states, none of them an unexplained blank:
     named      the name and its kind
     own        the target is the account that acted (signing in, changing a
                password) — said in words, not left as the actor's email twice
     gone       it has been deleted since; its short id stays, for matching
                against a backup or an export
     none       the event acts on no single record */
const TARGET_ICON: Record<string, ComponentType<{ size?: number; className?: string }>> = {
  Device: IconDevices,
  User: IconUsers,
  Credential: IconKey,
  Session: IconSessions,
  Recording: IconFilm,
  Role: IconShield,
  "Device group": IconFolder,
  Team: IconUsers,
  "API token": IconKey,
  Setting: IconSettings,
};

function TargetCell({ row }: { row: Row }) {
  const kind = row.target_kind || "";
  if (row.target_is_actor) return <span className="text-xs text-faint">Own account</span>;
  if (!kind && !row.target_label) return <span className="text-2xs text-faint">—</span>;

  const Icon = TARGET_ICON[kind];
  return (
    <span className="flex min-w-0 max-w-[11.5rem] items-start gap-2">
      {Icon && <Icon size={14} className="mt-0.5 shrink-0 text-faint" />}
      <span className="min-w-0 leading-tight">
        {row.target_label ? (
          <span className="block truncate text-sm text-fg" title={row.target_label}>
            {row.target_label}
          </span>
        ) : (
          <span className="block truncate text-xs italic text-faint" title={row.target_id ? `${row.target_type} ${row.target_id}` : undefined}>
            No longer exists{row.target_id ? ` (${row.target_id.slice(0, 8)})` : ""}
          </span>
        )}
        {kind && <span className="block text-2xs text-faint">{kind}</span>}
      </span>
    </span>
  );
}

function targetSortValue(row: Row): string {
  if (row.target_is_actor) return "own account";
  return row.target_label || row.target_kind || "";
}

/* ---- Event detail drawer ---------------------------------------------------
   Click any row to inspect the whole event: who, what, from where, on what, and
   the structured payload the action recorded (a device name, a session id,
   a failure cause…). This is what makes the log answer "what exactly happened". */
function AuditDetailDrawer({ event, onClose }: { event: Row; onClose: () => void }) {
  const dt = plausibleDate(event.ts);
  const detailEntries = Object.entries(event.detail ?? {});
  const TargetIcon = TARGET_ICON[event.target_kind ?? ""];

  return (
    <Drawer
      title={event.title || event.action}
      subtitle={GROUP[event.group ?? ""]?.label ?? "Event"}
      icon={GROUP[event.group ?? ""]?.icon ?? IconAudit}
      onClose={onClose}
      width="max-w-lg"
    >
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
          <DRow label="Who">{event.actor || "GuardRail, by itself"}</DRow>
          {event.note && <DRow label="What">{event.note}</DRow>}
          <DRow label="On">
            {event.target_is_actor ? (
              <span className="text-sm text-fg">Their own account</span>
            ) : !event.target_kind && !event.target_label ? (
              <span className="text-xs text-faint">This event acts on no single record.</span>
            ) : (
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5">
                  {TargetIcon && <TargetIcon size={14} className="shrink-0 text-faint" />}
                  <span className="min-w-0 truncate text-sm text-fg">
                    {event.target_label || <span className="text-faint">no longer exists</span>}
                  </span>
                  {event.target_kind && <span className="shrink-0 text-2xs text-faint">{event.target_kind}</span>}
                </div>
                {event.target_id && <CopyableID label={event.target_type || "id"} value={event.target_id} />}
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
          <DRow label="Event code">
            <ActionName action={event.action} />
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

// fmtWhen is a date a person reads at a glance: the day only when it is not
// today, and the year only when it is not this one.
function fmtWhen(d: Date): string {
  const now = new Date();
  const time = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (d.toDateString() === now.toDateString()) return `Today, ${time}`;
  const day = d.toLocaleDateString([], {
    day: "numeric",
    month: "short",
    ...(d.getFullYear() !== now.getFullYear() ? { year: "numeric" } : {}),
  });
  return `${day}, ${time}`;
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
