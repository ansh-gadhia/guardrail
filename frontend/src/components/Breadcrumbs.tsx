import { Link, useLocation } from "react-router-dom";
import { IconHome, IconChevronRight } from "./icons";

const LABELS: Record<string, string> = {
  "": "Dashboard",
  devices: "Devices",
  access: "Access Control",
  sessions: "Sessions",
  recordings: "Recordings",
  "access-log": "Access Log",
  audit: "Audit Log",
  security: "Account",
  view: "Live session",
};

export function Breadcrumbs() {
  const { pathname } = useLocation();
  const parts = pathname.split("/").filter(Boolean);

  const crumbs = [{ to: "/", label: "Dashboard", home: true }];
  let acc = "";
  for (const p of parts) {
    acc += `/${p}`;
    // Skip opaque ids (uuids) — label them via the following segment instead.
    if (/^[0-9a-f-]{16,}$/i.test(p)) continue;
    crumbs.push({ to: acc, label: LABELS[p] ?? p, home: false });
  }

  return (
    <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <span key={c.to} className="flex min-w-0 items-center gap-1.5">
            {i > 0 && <IconChevronRight size={14} className="shrink-0 text-faint" />}
            {last ? (
              <span className="truncate font-medium text-fg">
                {c.home && <IconHome size={14} className="mr-1 inline text-faint" />}
                {c.label}
              </span>
            ) : (
              <Link to={c.to} className="flex items-center gap-1 truncate text-muted transition hover:text-fg">
                {c.home && <IconHome size={14} />}
                <span className="truncate">{c.label}</span>
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
