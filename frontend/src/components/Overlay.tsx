import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * The overlay layer: everything that must float above the application chrome.
 *
 * ## Why a portal, and not just a bigger z-index
 *
 * The app shell renders its page content into `<main class="isolate">`, and
 * `isolation: isolate` creates a stacking context. Anything a page renders is
 * therefore sealed inside `<main>`, and its z-index is only meaningful against
 * its siblings in there. The header (`z-30`) and the footer (`z-20`) are
 * positioned elements OUTSIDE that context, so they paint above the whole of
 * `<main>` — including a modal that asked for `z-50` and got it, locally, in a
 * context that loses to both.
 *
 * Raising the number cannot fix that; the comparison never happens. Every modal
 * and drawer in the application was rendered from a page, so every one of them
 * was sliced by the header along its top edge and the footer along its bottom.
 *
 * Portalling to `document.body` moves them out of the sealed context entirely,
 * where the z-scale below is finally compared against the chrome.
 *
 * ## The scale
 *
 * One place decides what covers what, so it cannot drift:
 *
 *   80  dialogs — modals and drawers
 *   90  command palette (opens over an already-open dialog)
 *  100  toasts (must be readable above everything, including the palette)
 */
export const Z = {
  dialog: 80,
  palette: 90,
  toast: 100,
} as const;

/** Renders children into document.body, outside every page stacking context. */
export function Portal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}

// Nested overlays are real — a confirm dialog opens over a drawer — so the lock
// counts holders rather than assuming one. The last one out restores whatever
// the document had before the first one arrived, which is not necessarily "".
let scrollLocks = 0;
let priorOverflow = "";

function lockScroll() {
  if (scrollLocks === 0) {
    priorOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  scrollLocks += 1;
}

function releaseScroll() {
  scrollLocks = Math.max(0, scrollLocks - 1);
  if (scrollLocks === 0) document.body.style.overflow = priorOverflow;
}

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/**
 * Dialog behaviour shared by Modal and Drawer: Escape closes, the page behind
 * stops scrolling, focus moves into the panel and is returned to whatever
 * opened it, and Tab cycles inside rather than walking off into the page
 * underneath — which, with the panel portalled out of the DOM order, would
 * otherwise send the caret somewhere the user cannot see.
 */
export function useDialog(onClose: () => void) {
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    lockScroll();

    // Focus the panel itself rather than its first control: a detail drawer's
    // first control is the close button, and focusing that reads as "you are
    // about to dismiss this" the moment it opens.
    panel.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panel.current) return;
      const items = Array.from(panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null,
      );
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || active === panel.current)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      releaseScroll();
      opener?.focus?.();
    };
  }, [onClose]);

  return panel;
}
