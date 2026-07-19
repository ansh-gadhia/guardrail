// A slim brand strip pinned below the scrolling content: a flowing accent beam on
// its top edge and a single shimmering tagline. The company mark used to sit here
// but reads better up beside the product wordmark now (see the brand seal in
// AppLayout), so the footer is kept to one quiet, centred line. All motion is
// CSS-only and honours reduced-motion.
export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="footer-rise relative z-20 shrink-0 overflow-hidden border-t border-line bg-surface/50 backdrop-blur">
      <span className="footer-beam pointer-events-none absolute inset-x-0 top-0 h-px" aria-hidden />
      <div className="mx-auto flex w-full max-w-7xl items-center justify-center px-4 py-1.5 sm:px-6">
        <p className="footer-shimmer truncate font-display text-2xs font-semibold tracking-tight sm:text-xs">
          Privileged access, brokered and recorded. · © {year}
        </p>
      </div>
    </footer>
  );
}
