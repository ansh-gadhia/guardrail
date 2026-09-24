import { CompanyLogo } from "./brand";
import { useBranding } from "@/hooks/useBranding";

/**
 * The brand strip pinned below the scrolling content.
 *
 * Its top edge is a beam in the product's and the vendor's colours — teal and
 * cyan from GuardRail, the green and red of the Virtual Galaxy mark — flowing
 * along the rule, with a soft glow bleeding into the strip beneath it and a
 * spark that runs the length of it every few seconds. Below: what the product
 * does, who it is running for when the console is branded, and who built it.
 *
 * It is the height of the sidebar's foot, so the rule above it continues the
 * one under the sidebar and runs straight across the app. All motion is CSS and
 * stops under reduced motion.
 */
export function Footer() {
  const year = new Date().getFullYear();
  const branding = useBranding();
  const client = branding.data?.configured ? branding.data : null;

  return (
    // No border: the beam is the edge. Clipped, so the spark leaving the right
    // end cannot scroll the page sideways.
    <footer className="relative z-20 flex h-12 shrink-0 items-center overflow-hidden bg-surface/70 backdrop-blur">
      <span className="footer-glow" aria-hidden />
      <span className="footer-beam" aria-hidden />
      <span className="footer-spark" aria-hidden />

      <div className="mx-auto flex w-full max-w-7xl items-center justify-center gap-x-3.5 px-4 sm:px-6">
        <p className="footer-shimmer hidden truncate font-display text-xs font-semibold tracking-tight sm:block">
          Privileged access, brokered and recorded.
        </p>

        {client && (
          <>
            <Node className="hidden md:block" />
            {/* Whatever was supplied, and only that: a logo alone, a name alone,
                or the logo with the name beside it. */}
            <span className="hidden min-w-0 items-center gap-1.5 text-xs text-faint md:inline-flex">
              Deployed for
              {client.client_logo && (
                <img
                  src={client.client_logo}
                  alt={client.client_name || "Client logo"}
                  draggable={false}
                  className="h-4 w-auto max-w-[96px] select-none object-contain"
                />
              )}
              {client.client_name.trim() && (
                <span className="max-w-[160px] truncate font-medium text-muted">{client.client_name}</span>
              )}
            </span>
          </>
        )}

        <Node className="hidden sm:block" />

        <a
          href="https://vgipl.com"
          target="_blank"
          rel="noreferrer noopener"
          className="footer-mark inline-flex shrink-0 items-center gap-2 rounded outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
        >
          <span className="text-xs text-faint">Engineered by</span>
          <CompanyLogo className="h-[18px] w-auto" />
        </a>

        <Node />
        <span className="shrink-0 text-xs tabular-nums text-faint">© {year}</span>
      </div>
    </footer>
  );
}

// A small lit node between the items, like a stop on the rail above them.
function Node({ className = "" }: { className?: string }) {
  return <span className={`footer-node h-1 w-1 shrink-0 rounded-full ${className}`} aria-hidden />;
}
