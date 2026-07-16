import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { api } from "@/lib/api";
import type { SearchResults } from "@/lib/types";
import { cn } from "./ui";
import { IconSearch, IconDevices, IconSessions, IconUsers } from "./icons";

type IconType = ComponentType<{ size?: number; className?: string }>;

export interface Command {
  id: string;
  label: string;
  hint?: string;
  group: string;
  icon?: IconType;
  run: () => void;
}

/** Global ⌘K / Ctrl-K command palette. Fuzzy-filters static commands and merges
 *  live entity search results from GET /search. */
export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [q, setQ] = useState("");
  const [remote, setRemote] = useState<Command[]>([]);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setActive(0);
      setRemote([]);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  // Live entity search
  useEffect(() => {
    if (!open || q.trim().length < 2) {
      setRemote([]);
      return;
    }
    const t = setTimeout(async () => {
      try {
        const { data } = await api.get<SearchResults>("/search", { params: { q } });
        const mk = (group: string, icon: IconType, items: { id: string; label: string }[], to: (id: string) => void): Command[] =>
          items.map((it) => ({ id: `${group}:${it.id}`, label: it.label, group, icon, run: () => to(it.id) }));
        setRemote([
          ...mk("Devices", IconDevices, data.devices, () => nav("/devices")),
          ...mk("Sessions", IconSessions, data.sessions, () => nav("/sessions")),
          ...mk("Users", IconUsers, data.users, () => nav("/access")),
        ]);
      } catch {
        setRemote([]);
      }
    }, 180);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, open]);

  const nav = (path: string) => {
    onClose();
    window.history.pushState({}, "", path);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    const base = query ? commands.filter((c) => c.label.toLowerCase().includes(query) || c.group.toLowerCase().includes(query)) : commands;
    return [...base, ...remote];
  }, [q, commands, remote]);

  useEffect(() => setActive(0), [filtered.length]);

  if (!open) return null;

  const groups = Array.from(new Set(filtered.map((c) => c.group)));

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      filtered[active]?.run();
    } else if (e.key === "Escape") {
      onClose();
    }
  };

  let idx = -1;
  return (
    <div className="fixed inset-0 z-[90] flex items-start justify-center p-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-fadein" onClick={onClose} />
      <div className="relative z-10 w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-surface shadow-md animate-slideup">
        <div className="flex items-center gap-3 border-b border-line px-4">
          <IconSearch size={18} className="text-faint" />
          <input
            ref={inputRef}
            className="w-full bg-transparent py-3.5 text-sm text-fg placeholder-faint outline-none"
            placeholder="Search or jump to…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <kbd className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-2xs text-faint">esc</kbd>
        </div>
        <div className="max-h-[52vh] overflow-auto p-2">
          {filtered.length === 0 && <div className="px-3 py-6 text-center text-sm text-muted">No matches.</div>}
          {groups.map((group) => (
            <div key={group} className="mb-1">
              <div className="px-2 py-1 text-2xs font-semibold uppercase tracking-wider text-faint">{group}</div>
              {filtered
                .filter((c) => c.group === group)
                .map((c) => {
                  idx++;
                  const i = idx;
                  const Icon = c.icon;
                  return (
                    <button
                      key={c.id}
                      onMouseEnter={() => setActive(i)}
                      onClick={() => c.run()}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left text-sm transition",
                        i === active ? "bg-accent/12 text-accent" : "text-fg hover:bg-surface-2",
                      )}
                    >
                      {Icon && <Icon size={16} className={i === active ? "text-accent" : "text-faint"} />}
                      <span className="flex-1 truncate">{c.label}</span>
                      {c.hint && <span className="text-2xs text-faint">{c.hint}</span>}
                    </button>
                  );
                })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
