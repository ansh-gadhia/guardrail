import { CompanyLogo } from "./brand";
import { useBranding } from "@/hooks/useBranding";

/**
 * The brand strip pinned below the scrolling content.
 *
 * Three things sit on one line: what this product does, who built it, and — when
 * the console has been branded for a client — who it is running for. The vendor
 * mark belongs here rather than only in the sidebar rail, because that rail now
 * carries the client's identity on a branded install and the engineering credit
 * would otherwise disappear from the product entirely.
 *
 * The mark is deliberately quiet: dimmed and desaturated until it is hovered.
 * A footer that shouts is a footer people learn to stop reading. All motion is
 * CSS-only and honours reduced-motion.
 */
export function Footer() {
  const year = new Date().getFullYear();
  const branding = useBranding();
  const client = branding.data?.configured ? branding.data : null;

  return (
    <footer className="footer-rise relative z-20 shrink-0 overflow-hidden border-t border-line bg-surface/50 backdrop-blur">
      <span className="footer-beam pointer-events-none absolute inset-x-0 top-0 h-px" aria-hidden />
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-center gap-x-3 gap-y-1 px-4 py-1.5 sm:px-6">
        <p className="footer-shimmer truncate font-display text-2xs font-semibold tracking-tight sm:text-xs">
          Privileged access, brokered and recorded.
        </p>

        {client && (
          <>
            <span className="h-3 w-px shrink-0 bg-line-strong/70" aria-hidden />
            {/* Whatever was supplied, and only that: a logo alone, a name alone,
                or the logo with the name beside it. */}
            <span className="inline-flex min-w-0 items-center gap-1.5 text-2xs text-faint">
              Deployed for
              {client.client_logo && (
                <img
                  src={client.client_logo}
                  alt={client.client_name || "Client logo"}
                  draggable={false}
                  className="h-3.5 w-auto max-w-[90px] select-none object-contain"
                />
              )}
              {client.client_name.trim() && (
                <span className="truncate font-medium text-muted">{client.client_name}</span>
              )}
            </span>
          </>
        )}

        <span className="h-3 w-px shrink-0 bg-line-strong/70" aria-hidden />

        <a
          href="https://vgipl.com"
          target="_blank"
          rel="noreferrer noopener"
          title="Virtual Galaxy Infotech"
          className="footer-mark inline-flex items-center gap-1.5 rounded outline-none focus-visible:ring-2 focus-visible:ring-accent/50"
        >
          <span className="text-2xs text-faint">Engineered by</span>
          <CompanyLogo className="h-3.5 w-auto" />
        </a>

        <span className="h-3 w-px shrink-0 bg-line-strong/70" aria-hidden />
        <span className="shrink-0 text-2xs text-faint">© {year}</span>
      </div>
    </footer>
  );
}
