import brandMark from "@/assets/brand-mark.png";
import vgBlack from "@/assets/vglogo-black.png";
import vgWhite from "@/assets/vglogo-white.png";
import { cn } from "./ui";

// BrandMark is the product's emblem — a self-contained shield that reads on both
// light and dark surfaces, so a single artwork serves every theme (unlike the
// wordmark below). It replaces the former lettermark. Callers size it via
// className (it fills the box, object-contain preserving its aspect).
export function BrandMark({ className }: { className?: string }) {
  return (
    <img
      src={brandMark}
      alt="GuardRail"
      draggable={false}
      className={cn("select-none object-contain", className)}
    />
  );
}

// CompanyLogo is the Virtual Galaxy wordmark. It ships as two artworks — dark ink
// for light backgrounds, light ink for dark — swapped purely by the `.dark` class
// on <html>, so the switch is instant with no flash and no JS. Both are trimmed to
// matching bounds, so one height renders identically across the theme switch. Set
// the height on className; the images track it at width:auto.
//
// onDark forces the light-ink variant regardless of theme, for surfaces that are
// always dark (the sign-in brand rail) where the auto swap would pick the wrong one.
export function CompanyLogo({ className, onDark }: { className?: string; onDark?: boolean }) {
  if (onDark) {
    return (
      <span className={cn("inline-flex", className)}>
        <img src={vgWhite} alt="Virtual Galaxy" draggable={false} className="h-full w-auto select-none object-contain" />
      </span>
    );
  }
  return (
    <span className={cn("inline-flex", className)}>
      <img src={vgBlack} alt="Virtual Galaxy" draggable={false} className="h-full w-auto select-none object-contain dark:hidden" />
      <img src={vgWhite} alt="Virtual Galaxy" draggable={false} className="hidden h-full w-auto select-none object-contain dark:block" />
    </span>
  );
}

/**
 * ClientWordmark renders a client's name as a mark rather than as a label.
 *
 * A name typed into a settings field has to hold the same position a logo would,
 * so it is set in the display face with the accent gradient clipped to the
 * letterforms — the same ink the product emblem uses. Plain body text in that
 * slot reads as a caption that has lost its image.
 */
export function ClientWordmark({ name, className }: { name: string; className?: string }) {
  return (
    <span className={cn("client-wordmark font-display", className)} title={name}>
      {name}
    </span>
  );
}

/**
 * BrandSeal is the block under the product wordmark: the client's identity when
 * one is configured, and the vendor mark when none is.
 *
 * Four cases, and each shows exactly what was supplied and nothing else:
 * a logo alone renders the logo, a name alone renders the name as a wordmark,
 * both renders the logo with the name set beneath it, and neither falls back to
 * the vendor seal. Substituting one for the other would mean an administrator
 * who uploaded artwork sees text, or one who typed a name sees a placeholder.
 *
 * It lives here rather than inside the sidebar because the settings page renders
 * exactly this component as a live preview. Two implementations would drift, and
 * a preview that does not match what ships is worse than no preview.
 */
export function BrandSeal({
  branding,
  compact,
}: {
  branding?: { client_name: string; client_logo: string; configured: boolean };
  compact?: boolean;
}) {
  const client = branding?.configured ? branding : null;
  const name = client?.client_name?.trim() ?? "";
  const logo = client?.client_logo ?? "";

  const inner = (
    <>
      <span className="text-[8.5px] font-semibold uppercase tracking-[0.24em] text-faint transition-colors group-hover:text-accent">
        {client ? "Secured for" : "Engineered by"}
      </span>
      <span className="seal-cluster relative flex flex-col items-center justify-center gap-1 px-3 py-0.5">
        <span className="seal-aura" aria-hidden />
        <span className="seal-star seal-star-1" aria-hidden />
        <span className="seal-star seal-star-2" aria-hidden />
        <span className="seal-star seal-star-3" aria-hidden />
        {client ? (
          <>
            {logo && (
              <img
                src={logo}
                alt={name || "Client logo"}
                draggable={false}
                className={cn(
                  "seal-logo relative w-auto max-w-full select-none object-contain",
                  compact ? "h-6" : "h-8",
                )}
              />
            )}
            {name && (
              <ClientWordmark
                name={name}
                className={cn(
                  "seal-logo relative",
                  // Beneath a logo the name is a caption for it, so it steps down a
                  // size; on its own it IS the mark and holds the full weight.
                  logo ? "text-[11px] opacity-90" : compact ? "text-sm" : "text-base",
                )}
              />
            )}
          </>
        ) : (
          <CompanyLogo className={cn("seal-logo relative w-auto", compact ? "h-6" : "h-7")} />
        )}
      </span>
    </>
  );

  const shell =
    "group relative flex flex-col items-center gap-1.5 rounded-xl py-2 outline-none transition-colors hover:bg-surface-2/40 focus-visible:ring-2 focus-visible:ring-accent/50";

  // The vendor mark links out; a client's own mark does not — sending a client's
  // staff to the vendor's website from their own console is not a courtesy.
  return (
    <div className="brand-seal px-4 pb-2">
      <div className="seal-divider mb-2.5 h-px w-full" aria-hidden />
      {client ? (
        <div className={shell}>{inner}</div>
      ) : (
        <a href="https://vgipl.com" target="_blank" rel="noreferrer noopener" title="Virtual Galaxy" className={shell}>
          {inner}
        </a>
      )}
    </div>
  );
}
