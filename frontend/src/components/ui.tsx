import type { ReactNode, ComponentType, ButtonHTMLAttributes, InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { useEffect, useRef, useState } from "react";
import { IconX } from "./icons";

type IconType = ComponentType<{ size?: number; className?: string }>;

export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

/* Hairline — the signature 1px top-edge accent. Parent must be relative + overflow-hidden. */
export function Hairline({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent/50 to-transparent",
        className,
      )}
    />
  );
}

/* Card — base surface. */
export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("rounded-xl border border-line bg-surface shadow-sm", className)}>{children}</div>;
}

/* Panel — a titled card: header (icon chip + title + subtitle + actions) over a body. */
export function Panel({
  title,
  subtitle,
  icon: Icon,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: IconType;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("relative overflow-hidden rounded-xl card-grad shadow-sm", className)}>
      <Hairline />
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
          <div className="flex min-w-0 items-start gap-3">
            {Icon && (
              <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
                <Icon size={15} />
              </span>
            )}
            <div className="min-w-0">
              {title && <h2 className="truncate font-display text-sm font-semibold tracking-tight text-fg">{title}</h2>}
              {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

/* Badge — soft-filled pill with an inset ring, in 6 tones. */
type Tone = "neutral" | "accent" | "success" | "warn" | "danger" | "info";
const TONE: Record<Tone, string> = {
  neutral: "bg-surface-3 text-muted ring-1 ring-inset ring-line-strong/60",
  accent: "bg-accent/12 text-accent ring-1 ring-inset ring-accent/25",
  success: "bg-success/12 text-success ring-1 ring-inset ring-success/25",
  warn: "bg-warn/12 text-warn ring-1 ring-inset ring-warn/25",
  danger: "bg-danger/12 text-danger ring-1 ring-inset ring-danger/25",
  info: "bg-info/12 text-info ring-1 ring-inset ring-info/25",
};

export function Badge({
  children,
  tone = "neutral",
  dot,
  className,
}: {
  children: ReactNode;
  tone?: Tone;
  dot?: boolean;
  className?: string;
}) {
  return (
    <span className={cn("badge", TONE[tone], className)}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

const STATUS_TONE: Record<string, Tone> = {
  active: "success",
  approved: "success",
  success: "success",
  bound: "success",
  pending: "warn",
  ended: "neutral",
  expired: "neutral",
  disabled: "neutral",
  denied: "danger",
  failure: "danger",
  error: "danger",
};

export function StatusBadge({ value }: { value: string }) {
  const tone = STATUS_TONE[value.toLowerCase()] ?? "neutral";
  return (
    <Badge tone={tone} dot>
      {value}
    </Badge>
  );
}

/* Stat — KPI tile for card grids, with hover lift + ignite-on-hover hairline. */
export function Stat({
  label,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: IconType;
  tone?: "warn" | "danger" | "accent";
}) {
  const valueColor = tone === "warn" ? "text-warn" : tone === "danger" ? "text-danger" : "text-fg";
  return (
    <div className="group relative overflow-hidden rounded-xl card-grad p-4 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:shadow-md">
      <Hairline className="opacity-0 transition-opacity group-hover:opacity-100" />
      <div className="flex items-start justify-between gap-2">
        <span className="text-2xs font-medium uppercase tracking-wider text-faint">{label}</span>
        {Icon && (
          <span className="grid h-8 w-8 place-items-center rounded-lg accent-grad text-white shadow-sm ring-1 ring-white/15 transition-transform group-hover:scale-105">
            <Icon size={16} />
          </span>
        )}
      </div>
      <div className={cn("mt-2 font-display text-[1.7rem] font-semibold leading-none tracking-tight tabular-nums", valueColor)}>
        {value}
      </div>
      {sub && <div className="mt-1.5 text-xs text-muted">{sub}</div>}
    </div>
  );
}

/* PageHero — the calm command-center page banner. */
export function PageHero({
  icon: Icon,
  eyebrow,
  title,
  subtitle,
  actions,
  stats,
}: {
  icon?: IconType;
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  stats?: ReactNode;
}) {
  return (
    <div className="relative mb-5 overflow-hidden rounded-2xl border border-line bg-surface shadow-sm animate-fadein">
      <Hairline />
      <div className="pointer-events-none absolute -left-16 -top-20 h-56 w-56 rounded-full bg-accent/12 blur-3xl" />
      <div className="pointer-events-none absolute right-10 -top-24 h-56 w-56 rounded-full bg-info/10 blur-3xl" />
      <div className="relative flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          {Icon && (
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl accent-grad text-white shadow-md ring-1 ring-white/20">
              <Icon size={24} />
            </span>
          )}
          <div>
            {eyebrow && (
              <div className="text-2xs font-semibold uppercase tracking-[0.14em] text-accent/90">{eyebrow}</div>
            )}
            <h1 className="font-display text-2xl font-semibold tracking-tight text-fg">{title}</h1>
            {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
          </div>
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {stats && <div className="relative flex flex-wrap gap-2 border-t border-line px-5 py-3">{stats}</div>}
    </div>
  );
}

/* HeroStat — glassy KPI chip for the PageHero stats row. */
export function HeroStat({ icon: Icon, label, value, tone = "neutral" }: { icon?: IconType; label: string; value: ReactNode; tone?: Tone }) {
  return (
    <div className="flex items-center gap-2.5 rounded-xl border border-line bg-surface/70 px-3 py-2 shadow-xs backdrop-blur">
      {Icon && (
        <span className={cn("grid h-7 w-7 place-items-center rounded-lg", TONE[tone])}>
          <Icon size={14} />
        </span>
      )}
      <div className="leading-tight">
        <div className="text-sm font-semibold tabular-nums text-fg">{value}</div>
        <div className="text-2xs uppercase tracking-wider text-faint">{label}</div>
      </div>
    </div>
  );
}

/* Tabs — segmented control for detail/settings pages. */
export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: string; label: string; icon?: IconType }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="inline-flex rounded-xl border border-line bg-surface-2/60 p-1">
      {tabs.map((t) => {
        const on = t.id === active;
        const Icon = t.icon;
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-sm font-medium transition",
              on ? "bg-surface text-accent shadow-xs ring-1 ring-line" : "text-muted hover:bg-surface/60 hover:text-fg",
            )}
          >
            {Icon && <Icon size={15} />}
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="mb-4 block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1.5 block text-xs text-faint">{hint}</span>}
    </label>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions}
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-10 text-muted">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-line-strong border-t-accent" />
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton rounded-md", className)} />;
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-danger/25 bg-danger/10 px-4 py-3 text-sm text-danger">
      <IconX size={16} className="mt-0.5 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

export function EmptyState({
  message,
  title,
  icon: Icon,
  action,
}: {
  message: string;
  title?: string;
  icon?: IconType;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-line bg-surface/40 py-14 text-center">
      {Icon && (
        <span className="grid h-11 w-11 place-items-center rounded-xl bg-surface-2 text-faint">
          <Icon size={22} />
        </span>
      )}
      {title && <div className="text-sm font-medium text-fg">{title}</div>}
      <p className="max-w-sm text-sm text-muted">{message}</p>
      {action}
    </div>
  );
}

/* Modal — portal-free overlay with a hairline header and Escape-to-close. */
// Modal widths. The default `md` suits a form; `lg` fits side-by-side pickers;
// `xl` is for content that is itself the point (a recording player).
const MODAL_WIDTH = {
  md: "max-w-lg",
  lg: "max-w-3xl",
  xl: "max-w-6xl",
} as const;

export function Modal({
  title,
  onClose,
  children,
  footer,
  icon: Icon,
  size = "md",
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  icon?: IconType;
  size?: keyof typeof MODAL_WIDTH;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fadein" onClick={onClose} />
      <div
        className={cn(
          "relative z-10 w-full overflow-hidden rounded-2xl border border-line bg-surface shadow-md animate-slideup",
          MODAL_WIDTH[size],
        )}
      >
        <Hairline />
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div className="flex items-center gap-3">
            {Icon && (
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
                <Icon size={16} />
              </span>
            )}
            <h2 className="text-base font-semibold text-fg">{title}</h2>
          </div>
          <button className="rounded-lg p-1 text-faint transition hover:bg-surface-2 hover:text-fg" onClick={onClose} aria-label="Close">
            <IconX size={18} />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line bg-surface-2/40 px-5 py-4">{footer}</div>}
      </div>
    </div>
  );
}

/* ---- Drawer ----------------------------------------------------------------
   A right-side slide-in panel for inspecting a single record (audit event,
   session…). Wider reading surface than a centered Modal, and it doesn't yank
   focus to screen-center — the row you clicked stays roughly in place. */
export function Drawer({
  title,
  subtitle,
  onClose,
  children,
  footer,
  icon: Icon,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  icon?: IconType;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fadein" onClick={onClose} />
      <div className="relative z-10 flex h-full w-full max-w-md flex-col border-l border-line bg-surface shadow-overlay animate-drawer-in">
        <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex min-w-0 items-center gap-3">
            {Icon && (
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
                <Icon size={16} />
              </span>
            )}
            <div className="min-w-0">
              <h2 className="truncate font-display text-base font-semibold tracking-tight text-fg">{title}</h2>
              {subtitle && <p className="truncate text-xs text-muted">{subtitle}</p>}
            </div>
          </div>
          <button className="rounded-lg p-1 text-faint transition hover:bg-surface-2 hover:text-fg" onClick={onClose} aria-label="Close">
            <IconX size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line bg-surface-2/40 px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

/* ---- Button ----------------------------------------------------------------- */
type ButtonVariant = "primary" | "ghost" | "danger" | "subtle";
export function Button({
  variant = "ghost",
  size = "md",
  loading,
  icon: Icon,
  block,
  className,
  children,
  disabled,
  ...rest
}: {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  loading?: boolean;
  icon?: IconType;
  block?: boolean;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const cls = { primary: "btn-primary", ghost: "btn-ghost", danger: "btn-danger", subtle: "btn-subtle" }[variant];
  return (
    <button
      className={cn(cls, size === "sm" && "btn-sm", block && "w-full", className)}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? (
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent opacity-70" />
      ) : (
        Icon && <Icon size={size === "sm" ? 14 : 16} />
      )}
      {children}
    </button>
  );
}

/* ---- Inputs ----------------------------------------------------------------- */
export function Input({ invalid, className, ...rest }: { invalid?: boolean } & InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn("input", invalid && "input-invalid", className)} {...rest} />;
}
export function Select({ invalid, className, children, ...rest }: { invalid?: boolean } & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn("input", invalid && "input-invalid", className)} {...rest}>
      {children}
    </select>
  );
}
export function Textarea({ invalid, className, ...rest }: { invalid?: boolean } & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn("input", invalid && "input-invalid", className)} {...rest} />;
}

/* Switch — an accessible on/off toggle (role=switch), for enable/disable controls. */
export function Switch({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-accent" : "bg-surface-3",
      )}
    >
      <span
        className={cn(
          "inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform",
          checked ? "translate-x-[18px]" : "translate-x-0.5",
        )}
      />
    </button>
  );
}

/* ---- Menu (click popover) --------------------------------------------------- */
export function Menu({
  trigger,
  children,
  align = "right",
  className,
}: {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode;
  children: (close: () => void) => ReactNode;
  align?: "left" | "right";
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <div ref={ref} className="relative">
      {trigger({ open, toggle: () => setOpen((v) => !v) })}
      {open && (
        <div
          className={cn(
            "absolute z-40 mt-2 min-w-[12rem] overflow-hidden rounded-xl border border-line bg-surface p-1 shadow-md animate-fadein",
            align === "right" ? "right-0" : "left-0",
            className,
          )}
          role="menu"
        >
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

export function MenuItem({
  children,
  onClick,
  icon: Icon,
  tone,
}: {
  children: ReactNode;
  onClick?: () => void;
  icon?: IconType;
  tone?: "danger";
}) {
  return (
    <button
      role="menuitem"
      onClick={onClick}
      className={cn(
        "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition",
        tone === "danger" ? "text-danger hover:bg-danger/10" : "text-fg hover:bg-surface-2",
      )}
    >
      {Icon && <Icon size={15} />}
      {children}
    </button>
  );
}

/* StatCluster — a dense, hairline-divided instrument readout. Replaces the
   four-equal-stat-card grid: one figure per cell, display numerals, quiet
   labels, deliberately compact so it reads as an instrument, not a hero row. */
export function StatCluster({
  items,
  className,
}: {
  items: { label: string; value: ReactNode; tone?: "accent" | "warn" | "danger" | "success"; hint?: string }[];
  className?: string;
}) {
  const tones: Record<string, string> = {
    accent: "text-accent",
    warn: "text-warn",
    danger: "text-danger",
    success: "text-success",
  };
  return (
    <div className={cn("inline-flex items-stretch divide-x divide-line overflow-hidden rounded-xl border border-line bg-surface-2/40", className)}>
      {items.map((it, i) => (
        <div key={i} className="flex min-w-[5.75rem] flex-col items-center justify-center gap-0.5 px-4 py-2.5 text-center" title={it.hint}>
          <div className={cn("font-display text-xl font-semibold leading-none tabular-nums", it.tone ? tones[it.tone] : "text-fg")}>
            {it.value}
          </div>
          <div className="text-2xs uppercase tracking-wider text-faint">{it.label}</div>
        </div>
      ))}
    </div>
  );
}

/* Tooltip — CSS-driven hover/focus label. Lightweight, no portal. */
export function Tooltip({
  label,
  children,
  side = "top",
}: {
  label: ReactNode;
  children: ReactNode;
  side?: "top" | "bottom" | "left" | "right";
}) {
  const pos = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-1.5",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-1.5",
    left: "right-full top-1/2 -translate-y-1/2 mr-1.5",
    right: "left-full top-1/2 -translate-y-1/2 ml-1.5",
  }[side];
  return (
    <span className="group/tt relative inline-flex">
      {children}
      <span
        role="tooltip"
        className={cn(
          "pointer-events-none absolute z-50 whitespace-nowrap rounded-md border border-line bg-surface-3 px-2 py-1 text-2xs font-medium text-fg opacity-0 shadow-md transition-opacity duration-150 group-hover/tt:opacity-100 group-focus-within/tt:opacity-100",
          pos,
        )}
      >
        {label}
      </span>
    </span>
  );
}
