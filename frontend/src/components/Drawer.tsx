import type { ReactNode, ComponentType } from "react";
import { useEffect } from "react";
import { Hairline } from "./ui";
import { IconX } from "./icons";

type IconType = ComponentType<{ size?: number; className?: string }>;

/**
 * Right-anchored slide-over. Used for detail panels and multi-field forms that
 * are too large for a Modal. Closes on Escape or backdrop click.
 */
export function Drawer({
  title,
  subtitle,
  icon: Icon,
  onClose,
  children,
  footer,
  width = "max-w-md",
}: {
  title: string;
  subtitle?: string;
  icon?: IconType;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-fadein" onClick={onClose} />
      <div className={`relative z-10 flex h-full w-full ${width} flex-col overflow-hidden border-l border-line bg-surface shadow-md animate-drawer-in`}>
        <Hairline />
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex min-w-0 items-start gap-3">
            {Icon && (
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
                <Icon size={18} />
              </span>
            )}
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-fg">{title}</h2>
              {subtitle && <p className="mt-0.5 truncate text-xs text-muted">{subtitle}</p>}
            </div>
          </div>
          <button className="rounded-lg p-1 text-faint transition hover:bg-surface-2 hover:text-fg" onClick={onClose} aria-label="Close">
            <IconX size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line bg-surface-2/40 px-5 py-4">{footer}</div>}
      </div>
    </div>
  );
}
