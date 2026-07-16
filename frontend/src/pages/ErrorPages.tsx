import { Component, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Hairline } from "@/components/ui";
import { IconAlert, IconHome, IconSearch } from "@/components/icons";

function ErrorShell({
  code,
  title,
  message,
  icon,
  action,
}: {
  code: string;
  title: string;
  message: string;
  icon: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center px-4">
      <div className="app-aura pointer-events-none fixed inset-0" />
      <div className="app-grid pointer-events-none fixed inset-0 opacity-40" />
      <div className="relative w-full max-w-md overflow-hidden rounded-2xl border border-line bg-surface p-8 text-center shadow-md animate-slideup">
        <Hairline />
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-accent-soft text-accent ring-1 ring-inset ring-accent/15">
          {icon}
        </div>
        <div className="mt-4 text-2xs font-semibold uppercase tracking-[0.2em] text-faint">Error {code}</div>
        <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight text-fg">{title}</h1>
        <p className="mx-auto mt-2 max-w-sm text-sm text-muted">{message}</p>
        <div className="mt-6 flex justify-center gap-2">{action}</div>
      </div>
    </div>
  );
}

export function NotFoundPage() {
  return (
    <ErrorShell
      code="404"
      title="Page not found"
      message="The page you're looking for doesn't exist or may have been moved."
      icon={<IconSearch size={26} />}
      action={
        <Link to="/" className="btn-primary">
          <IconHome size={16} /> Back to dashboard
        </Link>
      }
    />
  );
}

/** Catches render-time errors and shows a styled 500 instead of a white screen. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error: unknown) {
    // eslint-disable-next-line no-console
    console.error("Unhandled UI error:", error);
  }
  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <ErrorShell
        code="500"
        title="Something went wrong"
        message="An unexpected error occurred while rendering this page. Reloading usually fixes it."
        icon={<IconAlert size={26} />}
        action={
          <button className="btn-primary" onClick={() => window.location.assign("/")}>
            <IconHome size={16} /> Reload app
          </button>
        }
      />
    );
  }
}
