import { CompanyLogo } from "./brand";

// A slim brand strip pinned below the scrolling content: a flowing accent beam on
// its top edge, a shimmering one-line tagline, and the company mark anchored
// lower-right in a soft pulsing halo that lifts on hover. Kept deliberately short
// (single row) so it costs little vertical space on every page. All motion is
// CSS-only and honours reduced-motion.
export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="footer-rise relative z-20 shrink-0 overflow-hidden border-t border-line bg-surface/50 backdrop-blur">
      <span className="footer-beam pointer-events-none absolute inset-x-0 top-0 h-px" aria-hidden />
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 py-1.5 sm:px-6">
        <p className="footer-shimmer min-w-0 truncate font-display text-2xs font-semibold tracking-tight sm:text-xs">
          Privileged access, brokered and recorded. · © {year}
        </p>
        <a
          href="https://vgipl.com"
          target="_blank"
          rel="noreferrer noopener"
          title="Virtual Galaxy"
          className="footer-float group relative shrink-0 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
        >
          <span className="footer-logo-glow pointer-events-none absolute -inset-2 rounded-full" aria-hidden />
          <CompanyLogo className="relative h-6 w-auto transition-transform duration-300 group-hover:scale-[1.06] sm:h-7" />
        </a>
      </div>
    </footer>
  );
}
