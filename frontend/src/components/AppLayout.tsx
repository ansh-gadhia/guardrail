import { useEffect, useMemo, useState, type ComponentType } from "react";
import { NavLink, Outlet, useLocation, useNavigate, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/store/auth";
import { useTheme } from "@/store/theme";
import { useVersion } from "@/hooks/useVersion";
import { api } from "@/lib/api";
import type { Session } from "@/lib/types";
import { Breadcrumbs } from "./Breadcrumbs";
import { CommandPalette, type Command } from "./CommandPalette";
import { Menu, MenuItem, Badge, cn } from "./ui";
import {
  IconDashboard, IconDevices, IconSessions, IconSliders, IconAudit, IconShield,
  IconLogout, IconBell, IconSun, IconMoon, IconMenu, IconChevronsLeft, IconSearch, IconX, IconActivity, IconFilm, IconGlobe,
} from "./icons";

type IconType = ComponentType<{ size?: number; className?: string }>;
interface NavItem { to: string; label: string; icon: IconType; end?: boolean; perm?: string; section: string; }

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: IconDashboard, end: true, section: "Overview" },
  { to: "/devices", label: "Devices", icon: IconDevices, perm: "device:read", section: "Access" },
  { to: "/sessions", label: "Sessions", icon: IconSessions, perm: "session:read", section: "Access" },
  { to: "/recordings", label: "Recordings", icon: IconFilm, perm: "session:read", section: "Access" },
  { to: "/access", label: "Access Control", icon: IconSliders, perm: "user:read", section: "Governance" },
  { to: "/access-log", label: "Access Log", icon: IconActivity, perm: "user:read", section: "Governance" },
  { to: "/audit", label: "Audit Log", icon: IconAudit, perm: "log:read", section: "Governance" },
  { to: "/security", label: "Account", icon: IconShield, section: "Governance" },
];

const COLLAPSE_KEY = "guardrail-sidebar-collapsed";

export function AppLayout() {
  const { principal, logout } = useAuth();
  const has = useAuth((s) => s.has);
  const version = useVersion();
  const navigate = useNavigate();
  const location = useLocation();
  const { theme, toggle } = useTheme();

  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem(COLLAPSE_KEY) === "1"; } catch { return false; }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const nav = NAV.filter((n) => !n.perm || has(n.perm));
  const sections = Array.from(new Set(nav.map((n) => n.section)));

  useEffect(() => {
    try { localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0"); } catch { /* ignore */ }
  }, [collapsed]);

  // Close the mobile drawer on navigation.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  // ⌘K / Ctrl-K opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const onLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  // Notifications = live active sessions (real API data). The bell surfaces what
  // is happening on the platform right now — who is connected to what.
  const liveSessions = useQuery<Session[]>({
    queryKey: ["sessions", "active"],
    queryFn: async () => (await api.get<{ data: Session[] }>("/sessions/active")).data.data,
    refetchInterval: 15000,
    enabled: !!principal && has("session:read"),
  });
  const liveCount = liveSessions.data?.length ?? 0;

  const commands: Command[] = useMemo(() => {
    const navCmds: Command[] = nav.map((n) => ({
      id: `nav:${n.to}`, label: n.label, group: "Navigate", icon: n.icon, hint: "Go", run: () => { setPaletteOpen(false); navigate(n.to); },
    }));
    const actions: Command[] = [
      { id: "act:theme", label: `Switch to ${theme === "dark" ? "light" : "dark"} theme`, group: "Actions", icon: theme === "dark" ? IconSun : IconMoon, run: () => { setPaletteOpen(false); toggle(); } },
      { id: "act:account", label: "Account settings", group: "Actions", icon: IconShield, run: () => { setPaletteOpen(false); navigate("/security"); } },
      { id: "act:logout", label: "Sign out", group: "Actions", icon: IconLogout, run: () => { setPaletteOpen(false); void onLogout(); } },
    ];
    return [...navCmds, ...actions];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nav, theme]);

  const initials = (principal?.email ?? "?").slice(0, 2).toUpperCase();

  const SidebarInner = ({ collapsed }: { collapsed: boolean }) => (
    <>
      <div className={cn("flex items-center gap-2.5 px-5 py-5", collapsed && "justify-center px-0")}>
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl accent-grad font-bold text-white shadow-md ring-1 ring-white/20">G</div>
        {!collapsed && (
          <div>
            <div className="font-display text-[15px] font-semibold leading-none tracking-tight text-fg">GuardRail</div>
            <div className="mt-1 text-2xs uppercase tracking-wider text-faint">Privileged Access</div>
          </div>
        )}
      </div>
      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-2">
        {sections.map((section) => (
          <div key={section}>
            {!collapsed && <div className="px-3 pb-1.5 text-2xs font-semibold uppercase tracking-wider text-faint">{section}</div>}
            <div className="space-y-0.5">
              {nav.filter((n) => n.section === section).map((n) => {
                const Icon = n.icon;
                return (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    end={n.end}
                    title={collapsed ? n.label : undefined}
                    className={({ isActive }) =>
                      cn(
                        "relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all",
                        collapsed && "justify-center px-0",
                        isActive ? "nav-active-bar bg-accent/10 text-accent ring-1 ring-inset ring-accent/15" : "text-muted hover:bg-surface-2 hover:text-fg",
                      )
                    }
                  >
                    <Icon size={17} />
                    {!collapsed && <span className="flex-1">{n.label}</span>}
                    {!collapsed && n.to === "/sessions" && liveCount > 0 && <Badge tone="success">{liveCount}</Badge>}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t border-line p-3">
        <div className={cn("mt-1 flex items-center px-2 text-2xs text-faint", collapsed ? "justify-center" : "justify-between")}>
          {!collapsed && <span>GuardRail</span>}
          <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono">v{version.data?.version ?? "…"}</span>
        </div>
      </div>
    </>
  );

  return (
    <div className="relative flex h-screen overflow-hidden">
      <div className="app-aura pointer-events-none fixed inset-0 -z-10" />
      <div className="app-grid pointer-events-none fixed inset-0 -z-10 opacity-40" />

      {/* Desktop sidebar */}
      <aside className={cn("hidden shrink-0 flex-col border-r border-line bg-surface/70 backdrop-blur transition-[width] duration-200 lg:flex", collapsed ? "w-16" : "w-64")}>
        <SidebarInner collapsed={collapsed} />
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm animate-fadein" onClick={() => setMobileOpen(false)} />
          <aside className="animate-drawer-in relative flex h-full w-64 flex-col border-r border-line bg-surface">
            <button className="absolute right-3 top-4 rounded-lg p-1 text-faint hover:text-fg" onClick={() => setMobileOpen(false)} aria-label="Close menu"><IconX size={18} /></button>
            <SidebarInner collapsed={false} />
          </aside>
        </div>
      )}

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="relative z-30 flex items-center justify-between gap-4 border-b border-line bg-surface/60 px-4 py-2.5 backdrop-blur sm:px-6">
          <div className="flex min-w-0 items-center gap-2">
            <button className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu"><IconMenu size={18} /></button>
            <button className="hidden rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg lg:block" onClick={() => setCollapsed((v) => !v)} aria-label="Toggle sidebar" title="Toggle sidebar"><IconChevronsLeft size={18} className={cn("transition-transform", collapsed && "rotate-180")} /></button>
            <div className="hidden min-w-0 sm:block"><Breadcrumbs /></div>
          </div>

          <div className="flex items-center gap-1.5">
            {/* Command palette trigger */}
            <button
              onClick={() => setPaletteOpen(true)}
              className="hidden items-center gap-2 rounded-lg border border-line bg-surface-2/60 px-3 py-1.5 text-sm text-muted transition hover:border-line-strong hover:text-fg sm:flex"
            >
              <IconSearch size={15} />
              <span>Search…</span>
              <kbd className="rounded border border-line bg-surface px-1.5 py-0.5 text-2xs">⌘K</kbd>
            </button>
            <button className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg sm:hidden" onClick={() => setPaletteOpen(true)} aria-label="Search"><IconSearch size={18} /></button>

            {/* Notifications */}
            <Menu
              trigger={({ toggle }) => (
                <button className="relative rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg" onClick={toggle} aria-label="Notifications">
                  <IconBell size={18} />
                  {liveCount > 0 && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-success ring-2 ring-surface" />}
                </button>
              )}
            >
              {(close) => (
                <div className="w-72 p-1">
                  <div className="px-2.5 py-2 text-2xs font-semibold uppercase tracking-wider text-faint">Active sessions</div>
                  {liveCount === 0 ? (
                    <div className="px-2.5 py-4 text-center text-sm text-muted">No sessions are live right now.</div>
                  ) : (
                    <>
                      {(liveSessions.data ?? []).slice(0, 5).map((s) => (
                        <button key={s.id} onClick={() => { close(); navigate("/sessions"); }} className="flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-surface-2">
                          <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-lg bg-success/12 text-success"><IconSessions size={13} /></span>
                          <span className="min-w-0">
                            <span className="block truncate text-sm text-fg">Live session · {s.protocol?.toUpperCase() || "HTTPS"}</span>
                            <span className="flex items-center gap-1 text-2xs text-faint"><IconGlobe size={11} />{s.client_ip || "unknown source"}</span>
                          </span>
                        </button>
                      ))}
                      <button onClick={() => { close(); navigate("/sessions"); }} className="mt-1 block w-full rounded-lg px-2.5 py-2 text-center text-xs font-medium text-accent hover:bg-surface-2">View all sessions</button>
                    </>
                  )}
                </div>
              )}
            </Menu>

            {/* Theme switch */}
            <button className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg" onClick={toggle} aria-label="Toggle theme" title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
              {theme === "dark" ? <IconSun size={18} /> : <IconMoon size={18} />}
            </button>

            {/* Profile */}
            <Menu
              trigger={({ toggle }) => (
                <button className="flex items-center gap-2 rounded-lg p-1 pr-2 hover:bg-surface-2" onClick={toggle} aria-label="Account menu">
                  <span className="grid h-7 w-7 place-items-center rounded-full bg-accent-soft text-2xs font-semibold text-accent ring-1 ring-inset ring-accent/20">{initials}</span>
                </button>
              )}
            >
              {(close) => (
                <div className="w-56">
                  <div className="border-b border-line px-3 py-2.5">
                    <div className="truncate text-sm font-medium text-fg">{principal?.email}</div>
                    <div className="truncate text-2xs text-faint">{principal?.is_super_admin ? "Super Admin" : principal?.roles.join(", ") || "No roles"}</div>
                  </div>
                  <div className="p-1">
                    <MenuItem icon={IconShield} onClick={() => { close(); navigate("/security"); }}>Account settings</MenuItem>
                    <MenuItem icon={theme === "dark" ? IconSun : IconMoon} onClick={() => { close(); toggle(); }}>Toggle theme</MenuItem>
                    <MenuItem icon={IconLogout} tone="danger" onClick={() => { close(); void onLogout(); }}>Sign out</MenuItem>
                  </div>
                </div>
              )}
            </Menu>
          </div>
        </header>

        <main key={location.pathname} className="page-enter isolate mx-auto w-full max-w-7xl flex-1 overflow-auto px-4 pb-20 pt-6 sm:px-5">
          <Outlet />
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}
