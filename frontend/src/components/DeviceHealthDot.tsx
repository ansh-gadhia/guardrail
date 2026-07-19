import type { Device, DeviceHealth } from "@/lib/types";
import { plausibleDate } from "@/lib/dates";
import { Badge, cn } from "./ui";

/* A small reachability indicator: a pulsing green dot when the device's
   management endpoint answered the last probe, red when it didn't, and a muted
   dot while liveness is still unknown (never polled / poller off). */
const META = {
  online: { dot: "bg-success", ring: "bg-success/40", label: "Online" },
  offline: { dot: "bg-danger", ring: "bg-danger/40", label: "Offline" },
  unknown: { dot: "bg-muted", ring: "bg-muted/30", label: "Unknown" },
} as const;

function healthTitle(health: DeviceHealth | undefined, label: string): string {
  const checked = plausibleDate(health?.checked_at);
  return `${label}${health?.latency_ms != null ? ` · ${health.latency_ms} ms` : ""}${
    checked ? ` · checked ${checked.toLocaleTimeString()}` : ""
  }`;
}

export function DeviceHealthDot({ health, showLabel }: { health?: DeviceHealth; showLabel?: boolean }) {
  const status = (health?.status ?? "unknown") as keyof typeof META;
  const m = META[status] ?? META.unknown;
  return (
    <span className="inline-flex items-center gap-1.5" title={healthTitle(health, m.label)}>
      <span className="relative flex h-2 w-2">
        {status === "online" && (
          <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-75", m.ring)} />
        )}
        <span className={cn("relative inline-flex h-2 w-2 rounded-full", m.dot)} />
      </span>
      {showLabel && <span className="text-2xs text-muted">{m.label}</span>}
    </span>
  );
}

const TONE = { online: "success", offline: "danger", unknown: "neutral" } as const;

/* The device's headline state.
   Reachability, not lifecycle. `status` is a lifecycle field — it reads "active"
   for every registered device, including one whose address is invented and has
   never answered a probe. Showing it here put a green "active" chip next to a red
   offline dot and told the operator two opposite things about the same device;
   the one they actually came to find out is whether it answers.
   Lifecycle only appears when it is NOT active, because "disabled" is a real
   thing to know and it makes reachability moot. */
export function DeviceStatusBadge({ device }: { device: Device }) {
  if (device.status && device.status.toLowerCase() !== "active") {
    return (
      <Badge tone="neutral" dot>
        {device.status}
      </Badge>
    );
  }
  const status = (device.health?.status ?? "unknown") as keyof typeof META;
  const m = META[status] ?? META.unknown;
  return (
    <span title={healthTitle(device.health, m.label)}>
      <Badge tone={TONE[status] ?? "neutral"} dot>
        {m.label}
      </Badge>
    </span>
  );
}
