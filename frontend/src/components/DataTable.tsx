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
}

type SortDir = "asc" | "desc";

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
}: DataTableProps<T>) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [page, setPage] = useState(0);
  const [hidden, setHidden] = useState<Set<string>>(new Set(columns.filter((c) => c.defaultHidden).map((c) => c.key)));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dense, setDense] = useState(false);

  const visibleCols = columns.filter((c) => !hidden.has(c.key));
  const cellText = (col: Column<T>, row: T) => (col.value ? col.value(row) : "");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => columns.some((c) => String(cellText(c, r)).toLowerCase().includes(q)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, query, columns]);

  const sorted = useMemo(() => {
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
  }, [filtered, sortKey, sortDir, columns]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const clampedPage = Math.min(page, pageCount - 1);
  const pageRows = sorted.slice(clampedPage * pageSize, clampedPage * pageSize + pageSize);

  const toggleSort = (key: string) => {
    if (sortKey !== key) {
      setSortKey(key);
      setSortDir("asc");
    } else if (sortDir === "asc") {
      setSortDir("desc");
    } else {
      setSortKey(null);
    }
  };

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

  const exportCsv = () => {
    const cols = visibleCols;
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const head = cols.map((c) => esc(c.header)).join(",");
    const body = sorted.map((r) => cols.map((c) => esc(String(cellText(c, r)))).join(",")).join("\n");
    const blob = new Blob([head + "\n" + body], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${exportName ?? "export"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
          {exportName && (
            <Button size="sm" variant="ghost" icon={IconDownload} onClick={exportCsv}>
              Export
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
        <div className="flex items-center justify-between gap-3 border-t border-line bg-surface-2/40 px-4 py-2.5 text-xs text-muted">
          <span>
            {sorted.length === 0 ? 0 : clampedPage * pageSize + 1}–{Math.min(sorted.length, (clampedPage + 1) * pageSize)} of {sorted.length}
          </span>
          <div className="flex items-center gap-1">
            <button
              className="rounded-md p-1.5 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
              disabled={clampedPage === 0}
              onClick={() => setPage(clampedPage - 1)}
              aria-label="Previous page"
            >
              <IconChevronLeft size={16} />
            </button>
            <span className="tabular-nums">
              {clampedPage + 1} / {pageCount}
            </span>
            <button
              className="rounded-md p-1.5 text-muted transition hover:bg-surface-2 hover:text-fg disabled:opacity-40"
              disabled={clampedPage >= pageCount - 1}
              onClick={() => setPage(clampedPage + 1)}
              aria-label="Next page"
            >
              <IconChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
