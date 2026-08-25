import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { absLocal, relTime, startedOf } from "@/lib/dates";
import type { Session, Paged, SessionStats } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { PageHero, StatCluster, Panel, Badge, StatusBadge, EmptyState, ErrorNote, Skeleton } from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { IconFilm, IconDevices } from "@/components/icons";
import { SessionDetail, HeldCell } from "@/components/SessionDetail";

/* ---- time + duration helpers (UTC in, local out; math on epoch millis) ---- */

/** Column keys the server can sort on (see access.SessionSortColumns). */
const SERVER_SORTABLE = new Set(["user", "device", "protocol", "status", "started", "duration", "ip"]);

/** Debounces a value so typing in the search box does not fire a query per keystroke. */
function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function RecordingsPage() {
  // Which session is open lives in the URL, not in component state, so it can be
  // linked to. An investigator quoting a session in a ticket, a reviewer sending
  // "look at this one" to a colleague, and the back button all need the same
  // thing: an address that names the session. Holding it in useState made every
  // session reachable only by retracing the clicks that found it.
  const [params, setParams] = useSearchParams();
  const openID = params.get("session");

  const openSession = useCallback(
    (s: Session) =>
      setParams(
        (prev) => {
          prev.set("session", s.id);
          return prev;
        },
        // A push, so Escape/back closes the panel rather than leaving the page.
        { replace: false },
      ),
    [setParams],
  );

  const closeSession = useCallback(
    () =>
      setParams(
        (prev) => {
          prev.delete("session");
          return prev;
        },
        { replace: true },
      ),
    [setParams],
  );

  // Paging, search and sort live here and travel to the server. The table is
  // handed exactly one page and told the real total.
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(12);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const search = useDebounced(query.trim(), 300);

  // Any change to what is being asked for restarts at page one — otherwise a
  // search that narrows to three rows leaves you on page nine looking at
  // nothing, which reads as "no results".
  useEffect(() => setPage(0), [search, sortKey, sortDir]);

  const listParams = useMemo(
    () => ({
      limit: pageSize,
      offset: page * pageSize,
      ...(search ? { q: search } : {}),
      ...(sortKey && SERVER_SORTABLE.has(sortKey) ? { sort: sortKey, dir: sortDir } : {}),
    }),
    [pageSize, page, search, sortKey, sortDir],
  );

  const sessions = useQuery<Paged<Session>>({
    queryKey: ["sessions", "page", listParams],
    queryFn: async () => (await api.get<Paged<Session>>("/sessions", { params: listParams })).data,
    refetchInterval: 10_000,
    // Keeps the previous page on screen while the next one loads, so paging does
    // not flash the empty state between requests.
    placeholderData: keepPreviousData,
  });

  // Counters come from their own endpoint and describe every session in the
  // tenant. They used to be computed from the fetched array, which meant they
  // silently stopped counting past the fetch limit.
  const stats = useQuery<SessionStats>({
    queryKey: ["session-stats"],
    queryFn: async () => (await api.get<SessionStats>("/sessions/stats")).data,
    refetchInterval: 10_000,
  });

  const rows = sessions.data?.data ?? [];
  const total = sessions.data?.total ?? 0;

  // A linked session is fetched by id: the row it names may be on page nine, or
  // filtered out by whatever search the reader happens to have typed, or older
  // than anything on screen. Seeding from the loaded page keeps a click instant
  // and reserves the request for links arriving cold.
  const linked = useQuery<Session>({
    queryKey: ["session", openID],
    queryFn: async () => (await api.get<Session>(`/sessions/${openID}`)).data,
    enabled: !!openID,
    initialData: () => rows.find((r) => r.id === openID),
    staleTime: 10_000,
  });
  const selected = linked.data ?? null;

  // Labels now ride along with each row, so this page no longer fetches every
  // user and every device just to name a dozen sessions.
  const deviceName = (s: Session) => s.device_name;
  const userEmail = (s: Session) => s.user_email;

  const columns: Column<Session>[] = [
    {
      key: "user",
      header: "User",
      value: (s) => userEmail(s) ?? s.user_id ?? "",
      cell: (s) => {
        const email = userEmail(s);
        return (
          <div className="flex items-center gap-2">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-full accent-grad text-2xs font-semibold text-white ring-1 ring-white/20">
              {(email ?? "··").slice(0, 2).toUpperCase()}
            </span>
            <span className="truncate text-sm text-fg">{email ?? <span className="font-mono text-xs text-faint">{(s.user_id ?? "").slice(0, 8)}</span>}</span>
          </div>
        );
      },
    },
    {
      key: "device",
      header: "Device",
      value: (s) => deviceName(s) ?? s.device_address ?? s.device_id,
      // The name is the one recorded at connect, so a session still names its
      // device after that device has been deleted. The address underneath answers
      // "which box was that" when the name has been reused or means nothing now.
      cell: (s) => (
        <div className="leading-tight">
          <span className="inline-flex items-center gap-1.5 text-sm text-fg">
            <IconDevices size={14} className="text-faint" />
            {deviceName(s) ?? <span className="font-mono text-xs text-faint">{s.device_id.slice(0, 8)}</span>}
          </span>
          {s.device_address && <div className="pl-[22px] font-mono text-2xs text-faint">{s.device_address}</div>}
        </div>
      ),
    },
    {
      key: "protocol",
      header: "Protocol",
      value: (s) => s.protocol,
      cell: (s) => <Badge tone="neutral">{s.protocol}</Badge>,
    },
    {
      key: "status",
      header: "Status",
      value: (s) => s.status,
      cell: (s) => <StatusBadge value={s.status} />,
    },
    {
      key: "started",
      header: "Started",
      value: (s) => startedOf(s) ?? "",
      cell: (s) => (
        <div className="leading-tight">
          <div className="whitespace-nowrap text-sm text-fg">{absLocal(startedOf(s))}</div>
          <div className="text-2xs text-faint">{relTime(startedOf(s))}</div>
        </div>
      ),
    },
    {
      key: "duration",
      header: "Held",
      value: (s) => {
        const st = startedOf(s);
        if (!st) return 0;
        const close = new Date(s.ended_at ?? Date.now()).getTime();
        const until = s.granted_until ? new Date(s.granted_until).getTime() : Infinity;
        return Math.max(0, Math.min(close, until) - new Date(st).getTime());
      },
      cell: (s) => <HeldCell session={s} />,
    },
    {
      key: "ip",
      header: "Client IP",
      value: (s) => s.client_ip ?? "",
      cell: (s) => <span className="font-mono text-xs text-faint">{s.client_ip || "—"}</span>,
      align: "right",
    },
  ];

  return (
    <div className="space-y-5">
      <PageHero
        icon={IconFilm}
        eyebrow="Access"
        title="Recordings"
        subtitle="Every brokered session — who reached which device, when, for how long, and what they did."
        stats={
          stats.data ? (
            <StatCluster
              items={[
                { label: "Sessions", value: stats.data.total },
                { label: "Active now", value: stats.data.active, tone: stats.data.active > 0 ? "accent" : undefined },
                { label: "Ended", value: stats.data.ended },
                { label: "Devices", value: stats.data.devices },
              ]}
            />
          ) : undefined
        }
      />

      <Panel title="Session recordings" icon={IconFilm} bodyClassName="p-0">
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : sessions.isError ? (
          <div className="p-4">
            <ErrorNote message="Couldn't load session recordings. Try reloading." />
          </div>
        ) : total === 0 && !search ? (
          <EmptyState icon={IconFilm} title="No sessions yet" message="Brokered device sessions and their activity will be recorded here." />
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(s) => s.id}
            searchPlaceholder="Search by user, device, IP, protocol…"
            exportName="session-recordings"
            emptyMessage={search ? `No sessions match “${search}”.` : "No results."}
            onRowClick={openSession}
            server={{
              total,
              page,
              onPageChange: setPage,
              pageSize,
              onPageSizeChange: setPageSize,
              query,
              onQueryChange: setQuery,
              sortKey,
              sortDir,
              onSortChange: (k, d) => {
                setSortKey(k);
                setSortDir(d);
              },
              loading: sessions.isFetching,
              // Export pulls the whole filtered set rather than the page on
              // screen. Capped so a tenant with a very long history cannot turn
              // one click into an unbounded response.
              fetchAll: async () => {
                const { data } = await api.get<Paged<Session>>("/sessions", {
                  params: { ...listParams, limit: 5000, offset: 0 },
                });
                return data.data;
              },
            }}
          />
        )}
      </Panel>

      {selected && (
        <SessionDetail
          session={selected}
          deviceLabel={deviceName(selected)}
          userLabel={userEmail(selected)}
          onClose={closeSession}
        />
      )}
      {/* A link to a session that no longer exists, or that this reader may not
          read, must say so — silently showing the list is indistinguishable from
          the link having worked. */}
      {openID && !selected && linked.isError && (
        <ErrorNote message="That session could not be opened — it may have been deleted, or it belongs to an organization you cannot read." />
      )}
    </div>
  );
}
