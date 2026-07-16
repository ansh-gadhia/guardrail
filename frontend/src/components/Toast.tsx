import { useEffect } from "react";
import { create } from "zustand";
import { cn } from "./ui";
import { IconCheck, IconAlert, IconX } from "./icons";

export type ToastTone = "success" | "error" | "warn" | "info";
interface Toast {
  id: number;
  tone: ToastTone;
  title: string;
  description?: string;
  ttl: number;
}

interface ToastState {
  toasts: Toast[];
  push: (t: Omit<Toast, "id">) => void;
  dismiss: (id: number) => void;
}

// A tiny monotonic id source (Date.now/Math.random are unavailable in some
// sandboxes; a counter is deterministic and collision-free within a session).
let seq = 1;

const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  push: (t) => set((s) => ({ toasts: [...s.toasts, { ...t, id: seq++ }] })),
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),
}));

function make(tone: ToastTone) {
  return (title: string, description?: string, ttl = 5000) =>
    useToastStore.getState().push({ tone, title, description, ttl });
}

/** Fire-and-forget toasts from anywhere: `toast.success("Saved")`. */
export const toast = {
  success: make("success"),
  error: make("error"),
  warn: make("warn"),
  info: make("info"),
};

const TONE_STYLES: Record<ToastTone, string> = {
  success: "border-success/30 text-success",
  error: "border-danger/30 text-danger",
  warn: "border-warn/30 text-warn",
  info: "border-info/30 text-info",
};

function ToastCard({ t }: { t: Toast }) {
  const dismiss = useToastStore((s) => s.dismiss);
  useEffect(() => {
    if (t.ttl <= 0) return;
    const timer = setTimeout(() => dismiss(t.id), t.ttl);
    return () => clearTimeout(timer);
  }, [t.id, t.ttl, dismiss]);

  const Icon = t.tone === "success" ? IconCheck : IconAlert;
  return (
    <div
      role="status"
      className="pointer-events-auto flex w-80 items-start gap-3 overflow-hidden rounded-xl border border-line bg-surface p-3.5 shadow-md animate-slideup"
    >
      <span className={cn("mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-lg border bg-surface-2", TONE_STYLES[t.tone])}>
        <Icon size={14} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{t.title}</div>
        {t.description && <div className="mt-0.5 text-xs text-muted">{t.description}</div>}
      </div>
      <button className="rounded p-0.5 text-faint transition hover:text-fg" onClick={() => dismiss(t.id)} aria-label="Dismiss">
        <IconX size={15} />
      </button>
    </div>
  );
}

/** Mount once near the app root. */
export function Toaster() {
  const toasts = useToastStore((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-[100] flex flex-col gap-2">
      {toasts.map((t) => (
        <ToastCard key={t.id} t={t} />
      ))}
    </div>
  );
}
