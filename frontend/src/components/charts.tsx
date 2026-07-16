import type { ReactNode } from "react";
import { cn } from "./ui";

// Dependency-free, token-themed SVG charts. Colors come from Tailwind text/stroke
// utilities (via currentColor), so they follow the active theme automatically —
// no chart library, no hardcoded hex.

export interface DonutSegment {
  value: number;
  /** Tailwind text-color class, applied via stroke="currentColor". */
  className: string;
  label?: string;
}

export function Donut({
  segments,
  size = 108,
  thickness = 12,
  centerLabel,
  centerSub,
}: {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  centerLabel?: ReactNode;
  centerSub?: ReactNode;
}) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  let offset = 0;
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={thickness} className="stroke-surface-3" />
        {segments.map((s, i) => {
          const len = (s.value / total) * c;
          const el = (
            <circle
              key={i}
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              strokeWidth={thickness}
              stroke="currentColor"
              strokeLinecap="round"
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
              className={cn(s.className, "transition-all duration-500")}
            />
          );
          offset += len;
          return el;
        })}
      </svg>
      {(centerLabel || centerSub) && (
        <div className="absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-2xl font-semibold tabular-nums text-fg">{centerLabel}</div>
            {centerSub && <div className="text-2xs uppercase tracking-wider text-faint">{centerSub}</div>}
          </div>
        </div>
      )}
    </div>
  );
}

export function Legend({ items }: { items: { label: string; value: number; className: string }[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((it) => (
        <li key={it.label} className="flex items-center gap-2 text-sm">
          <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full bg-current", it.className)} />
          <span className="text-muted">{it.label}</span>
          <span className="ml-auto tabular-nums font-medium text-fg">{it.value}</span>
        </li>
      ))}
    </ul>
  );
}

// A labelled horizontal progress ("posture") bar.
export function PostureBar({
  label,
  value,
  max,
  sub,
  barClassName = "accent-grad",
}: {
  label: ReactNode;
  value: number;
  max: number;
  sub?: ReactNode;
  barClassName?: string;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="truncate text-sm text-fg">{label}</span>
        <span className="shrink-0 text-xs tabular-nums text-muted">{sub ?? value}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-surface-3">
        <div
          className={cn("h-full rounded-full transition-[width] duration-500", barClassName)}
          style={{ width: `${value > 0 ? Math.max(pct, 4) : 0}%` }}
        />
      </div>
    </div>
  );
}
