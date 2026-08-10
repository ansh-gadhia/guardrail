import { useMemo, useState, type ReactNode } from "react";
import { Menu, MenuItem, Button, cn } from "./ui";
import { IconSearch, IconSort, IconChevronUp, IconChevronDown, IconColumns, IconRows, IconDownload, IconChevronLeft, IconChevronRight } from "./icons";

export interface Column<T> {
  key: string;
  header: string;
  /** Cell renderer. Falls back to String(sortValue). */
  cell?: (row: T) => ReactNode;
  /** Value used for sorting + search + CSV export. */
  value?: (row: T) => string | number;
  sortable?: boolean;
  align?: "left" | "right";
  className?: string;
  defaultHidden?: boolean;
}

type SortDir = "asc" | "desc";

/**
 * ServerMode hands paging, searching and sorting to the server.
 *
 * Without it the table does all three over whatever array it was given, which is
 * correct only when that array is the whole result set. On a listing that is
 * capped server-side it quietly becomes "of the rows we happened to fetch" —
 * the row count, the page count and the search all narrow to the slab, and
 * nothing on screen says so.
 *
 * `rows` in this mode is exactly one page; the table renders it as-is.
 */
export interface ServerMode<T> {
  /** Total rows matching the current filter, across all pages. */
  total: number;
  /** Zero-based page index. */
  page: number;
  onPageChange: (page: number) => void;
  pageSize: number;
  onPageSizeChange?: (size: number) => void;
  query: string;
  onQueryChange: (q: string) => void;
  sortKey: string | null;
  sortDir: SortDir;
  onSortChange: (key: string | null, dir: SortDir) => void;
  /** Shows a busy hint while a page is in flight. */
  loading?: boolean;
  /**
   * Supplies every matching row for CSV export. Without it the export button is
   * hidden in server mode rather than silently writing a one-page file under a
   * name that claims to be the whole table.
   */
  fetchAll?: () => Promise<T[]>;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  searchable?: boolean;
  searchPlaceholder?: string;
  pageSize?: number;
  selectable?: boolean;
  bulkActions?: (selected: T[], clear: () => void) => ReactNode;
  exportName?: string;
  emptyMessage?: string;
  onRowClick?: (row: T) => void;
  toolbar?: ReactNode;
  /** When set, the server owns paging/search/sort. */
  server?: ServerMode<T>;
}

const PAGE_SIZES = [12, 25, 50, 100];

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  searchable = true,
  searchPlaceholder = "Search…",
  pageSize = 10,
  selectable = false,
  bulkActions,
  exportName,
  emptyMessage = "No results.",
  onRowClick,
  toolbar,
  server,
}: DataTableProps<T>) {
  const [localQuery, setLocalQuery] = useState("");
  const [localSortKey, setLocalSortKey] = useState<string | null>(null);
  const [localSortDir, setLocalSortDir] = useState<SortDir>("asc");
  const [localPage, setLocalPage] = useState(0);

  // One set of names for both modes: everything below reads these, so the render
  // path does not fork on whether the server or the browser is in charge.
  const query = server ? server.query : localQuery;
  const sortKey = server ? server.sortKey : localSortKey;
  const sortDir = server ? server.sortDir : localSortDir;
  const page = server ? server.page : localPage;
  const effPageSize = server ? server.pageSize : pageSize;
  const setPage = (p: number) => (server ? server.onPageChange(p) : setLocalPage(p));
  const [hidden, setHidden] = useState<Set<string>>(new Set(columns.filter((c) => c.defaultHidden).map((c) => c.key)));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dense, setDense] = useState(false);

  const visibleCols = columns.filter((c) => !hidden.has(c.key));
  const cellText = (col: Column<T>, row: T) => (col.value ? col.value(row) : "");

  const filtered = useMemo(() => {
    if (server) return rows; // already filtered by the query that produced this page
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => columns.some((c) => String(cellText(c, r)).toLowerCase().includes(q)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, query, columns, server]);

  const sorted = useMemo(() => {
    if (server) return filtered; // already ordered by the database
    if (!sortKey) return filtered;
    const col = columns.find((c) => c.key === sortKey);
    if (!col?.value) return filtered;
    const dir = sortDir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const av = col.value!(a);
      const bv = col.value!(b);
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, sortKey, sortDir, columns, server]);

  // The row count the pager reports. In server mode it is the database's answer
  // for the whole filter, not the length of the page we were handed.
  const totalRows = server ? server.total : sorted.length;
  const pageCount = Math.max(1, Math.ceil(totalRows / effPageSize));
  const clampedPage = Math.min(page, pageCount - 1);
  const pageRows = server ? sorted : sorted.slice(clampedPage * effPageSize, clampedPage * effPageSize + effPageSize);
  const firstShown = totalRows === 0 ? 0 : clampedPage * effPageSize + 1;
  const lastShown = server ? Math.min(totalRows, clampedPage * effPageSize + pageRows.length) : Math.min(totalRows, (clampedPage + 1) * effPageSize);

  // Three-state cycle: unsorted → ascending → descending → unsorted.
  const toggleSort = (key: string) => {
    let nextKey: string | null = key;
    let nextDir: SortDir = "asc";
    if (sortKey === key) {
      if (sortDir === "asc") nextDir = "desc";
      else nextKey = null;
    }
    if (server) {
      server.onSortChange(nextKey, nextDir);
      return;
    }
    setLocalSortKey(nextKey);
    setLocalSortDir(nextDir);
  };

  const setQuery = (q: string) => (server ? server.onQueryChange(q) : setLocalQuery(q));

  const clearSel = () => setSelected(new Set());
  const toggleRow = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const pageIds = pageRows.map(rowKey);
  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selected.has(id));
  const toggleAll = () =>
    setSelected((s) => {
      const n = new Set(s);
      if (allOnPage) pageIds.forEach((id) => n.delete(id));
      else pageIds.forEach((id) => n.add(id));
      return n;
    });

  const selectedRows = rows.filter((r) => selected.has(rowKey(r)));

  const [exporting, setExporting] = useState(false);
  const writeCsv = (data: T[]) => {
    const cols = visibleCols;
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const head = cols.map((c) => esc(c.header)).join(",");
    const body = data.map((r) => cols.map((c) => esc(String(cellText(c, r)))).join(",")).join("\n");
    const blob = new Blob([head + "\n" + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${exportName ?? "export"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const exportCsv = async () => {
    if (!server) {
      writeCsv(sorted);
      return;
    }
    // In server mode `sorted` is one page. Writing that to a file named after the
    // whole table is the same lie the counters used to tell, so the rows are
    // fetched first.
    if (!server.fetchAll) return;
    setExporting(true);
    try {
      writeCsv(await server.fetchAll());
    } finally {
      setExporting(false);
    }
  };
  // Hidden rather than disabled when a server-mode table cannot produce the full
  // set: a greyed button invites a click that will never work.
  const canExport = !!exportName && (!server || !!server.fetchAll);

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        {searchable && (
          <div className="relative min-w-[14rem] flex-1">
            <IconSearch size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
            <input
              className="input pl-9"
              placeholder={searchPlaceholder}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
            />
          </div>
        )}
        {toolbar}
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="ghost"
            icon={IconRows}
            onClick={() => setDense((d) => !d)}
            aria-pressed={dense}
            title={dense ? "Comfortable rows" : "Compact rows"}
          >
            {dense ? "Comfortable" : "Compact"}
          </Button>
          <Menu
            trigger={({ toggle }) => (
              <Button size="sm" variant="ghost" icon={IconColumns} onClick={toggle}>
                Columns
              </Button>
            )}
          >
            {() => (
              <div className="p-1">
                {columns.map((c) => (
                  <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm text-fg hover:bg-surface-2">
                    <input
                      type="checkbox"
                      checked={!hidden.has(c.key)}
                      onChange={() =>
                        setHidden((h) => {
                          const n = new Set(h);
                          n.has(c.key) ? n.delete(c.key) : n.add(c.key);
                          return n;
                        })
                      }
                    />
                    {c.header}
                  </label>
                ))}
              </div>
            )}
          </Menu>
          {canExport && (
            <Button size="sm" variant="ghost" icon={IconDownload} onClick={exportCsv} disabled={exporting}>
              {exporting ? "Exporting…" : "Export"}
            </Button>
          )}
        </div>
      </div>

      {/* Bulk action bar */}
      {selectable && selectedRows.length > 0 && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-accent/25 bg-accent/10 px-3 py-2 text-sm">
          <span className="font-medium text-accent">{selectedRows.length} selected</span>
          <div className="flex items-center gap-2">
            {bulkActions?.(selectedRows, clearSel)}
            <button className="text-xs text-muted hover:text-fg" onClick={clearSel}>
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="overflow-hidden rounded-xl border border-line">
        <div className="max-h-[65vh] overflow-auto">
          <table className="w-full border-collapse">
            <thead className="sticky top-0 z-10 bg-surface-2/95 backdrop-blur">
              <tr className="border-b border-line">
                {selectable && (
                  <th className={cn("w-10 px-4", dense ? "py-1.5" : "py-2.5")}>
                    <input type="checkbox" checked={allOnPage} onChange={toggleAll} aria-label="Select all on page" />
                  </th>
                )}
                {visibleCols.map((c) => {
                  const active = sortKey === c.key;
                  const sortable = c.sortable !== false && !!c.value;
                  return (
                    <th
                      key={c.key}
                      className={cn("px-4 text-2xs font-semibold uppercase tracking-wider text-faint", dense ? "py-1.5" : "py-2.5", c.align === "right" ? "text-right" : "text-left")}
                    >
                      {sortable ? (
                        <button className="inline-flex items-center gap-1 transition hover:text-fg" onClick={() => toggleSort(c.key)}>
                          {c.header}
                          {active ? (
                            sortDir === "asc" ? (
                              <IconChevronUp size={13} />
                            ) : (
                              <IconChevronDown size={13} />
                            )
                          ) : (
                            <IconSort size={13} className="opacity-40" />
                          )}
                        </button>
                      ) : (
                        c.header
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {pageRows.length === 0 && (
                <tr>
                  <td colSpan={visibleCols.length + (selectable ? 1 : 0)} className="px-4 py-10 text-center text-sm text-muted">
                    {emptyMessage}
                  </td>
                </tr>
              )}
              {pageRows.map((row) => {
                const id = rowKey(row);
                return (
                  <tr
                    key={id}
                    className={cn("transition hover:bg-surface-2/50", onRowClick && "cursor-pointer", selected.has(id) && "bg-accent/5")}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                  >
                    {selectable && (
                      <td className={cn("w-10 px-4", dense ? "py-1.5" : "py-3")} onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(id)} onChange={() => toggleRow(id)} aria-label="Select row" />
                      </td>
                    )}
                    {visibleCols.map((c) => (
                      <td key={c.key} className={cn("px-4 text-sm text-fg", dense ? "py-1.5" : "py-3", c.align === "right" && "text-right", c.className)}>
                        {c.cell ? c.cell(row) : String(cellText(c, row))}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-t border-line bg-surface-2/40 px-4 py-2.5 text-xs text-muted">
          <div className="flex items-center gap-3">
            <span className="tabular-nums">
              {firstShown.toLocaleString()}–{lastShown.toLocaleString()} of {totalRows.toLocaleString()}
            </span>
            {server?.loading && <span className="text-faint">Loading…</span>}
          </div>
          <div className="flex items-center gap-3">
            {server?.onPageSizeChange && (
              <label className="flex items-center gap-1.5">
                <span className="text-faint">Rows</span>
                <select
                  className="rounded-md border border-line bg-surface px-1.5 py-1 text-xs text-fg"
                  value={effPageSize}
                  onChange={(e) => {
                    // Back to the first page: page 7 of the old size is a
                    // different set of rows at the new one.
                    server.onPageSizeChange?.(Number(e.target.value));
                    setPage(0);
                  }}
                >
                  {PAGE_SIZES.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="flex items-center gap-1">
              <button
                className="rounded-md px-1.5 py-1 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
                disabled={clampedPage === 0}
                onClick={() => setPage(0)}
                aria-label="First page"
              >
                ««
              </button>
              <button
                className="rounded-md p-1.5 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
                disabled={clampedPage === 0}
                onClick={() => setPage(clampedPage - 1)}
                aria-label="Previous page"
              >
                <IconChevronLeft size={16} />
              </button>
              <span className="tabular-nums">
                {(clampedPage + 1).toLocaleString()} / {pageCount.toLocaleString()}
              </span>
              <button
                className="rounded-md p-1.5 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
                disabled={clampedPage >= pageCount - 1}
                onClick={() => setPage(clampedPage + 1)}
                aria-label="Next page"
              >
                <IconChevronRight size={16} />
              </button>
              <button
                className="rounded-md px-1.5 py-1 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
                disabled={clampedPage >= pageCount - 1}
                onClick={() => setPage(pageCount - 1)}
                aria-label="Last page"
              >
                »»
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
