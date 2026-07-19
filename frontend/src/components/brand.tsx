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
