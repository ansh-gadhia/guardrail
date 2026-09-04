import { useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./store/auth";
import type { Principal } from "./lib/types";
import { AppLayout } from "./components/AppLayout";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DevicesPage } from "./pages/DevicesPage";
import { DeviceDetailPage } from "./pages/DeviceDetailPage";
import { AccessPage } from "./pages/AccessPage";
import { TeamsPage } from "./pages/TeamsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { SessionViewPage } from "./pages/SessionViewPage";
import { RecordingsPage } from "./pages/RecordingsPage";
import { AuditPage } from "./pages/AuditPage";
import { AccessLogPage } from "./pages/AccessLogPage";
import { SecurityPage } from "./pages/SecurityPage";
import { OrganizationPage } from "./pages/OrganizationPage";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { FirstRunPage } from "./pages/FirstRunPage";
import { SSOCallbackPage } from "./pages/SSOCallbackPage";
import { NotFoundPage, ErrorBoundary } from "./pages/ErrorPages";

// needsFirstRun reports whether there is something to put in front of somebody
// before the console itself.
//
// ONE RULE, both kinds of account. Somebody signing in for the first time is
// offered a second factor; everybody else goes straight in. A temporary password
// keeps its own clause because it is not optional — it must be replaced, however
// many times its owner reloads the page.
//
// It used to be keyed on the temporary password alone, and that quietly meant
// "only accounts an administrator typed a password for". An account provisioned
// by an identity provider has no password, so must_change_password is false and
// the whole first-run flow — including the two-factor offer at the end of it —
// was skipped. Every analyst arriving through single sign-on went straight into
// the console having never been asked, which is backwards: they are precisely
// the people it reaches privileged devices on behalf of.
//
// Once, not on every sign-in. The offer that comes back forever is the one
// people learn to click past, and somebody who declined it can still turn it on
// from Account -> Two-factor whenever they choose to.
function needsFirstRun(principal: Principal, firstRunDone: boolean): boolean {
  if (firstRunDone) return false;
  if (principal.must_change_password) return true;
  return principal.first_login && !principal.mfa_enabled;
}

function RequireAuth({ children }: { children: JSX.Element }) {
  const { principal, ready, firstRunDone } = useAuth();
  const location = useLocation();
  if (!ready) return <FullScreenSpinner />;
  if (!principal) return <Navigate to="/login" state={{ from: location }} replace />;
  // Gated here rather than on a route so it cannot be walked around by typing a
  // URL. It is still dismissible — see skipFirstRun — because a nag that cannot
  // be dismissed teaches people to click past security prompts.
  if (needsFirstRun(principal, firstRunDone)) return <FirstRunPage />;
  return children;
}

function FullScreenSpinner() {
  return (
    <div className="flex h-screen items-center justify-center text-muted">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-line-strong border-t-accent" />
    </div>
  );
}

export default function App() {
  const bootstrap = useAuth((s) => s.bootstrap);
  const ready = useAuth((s) => s.ready);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  if (!ready) return <FullScreenSpinner />;

  return (
    <ErrorBoundary>
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Where the SIEM drops the browser after it has authenticated somebody.
          Outside RequireAuth on purpose: the whole point is that there is no
          session yet, and the token in the URL fragment is what creates one. */}
      <Route path="/auth/sso" element={<SSOCallbackPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DeviceDetailPage />} />
        <Route path="/access" element={<AccessPage />} />
        <Route path="/teams" element={<TeamsPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:id/view" element={<SessionViewPage />} />
        <Route path="/recordings" element={<RecordingsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/access-log" element={<AccessLogPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/security" element={<SecurityPage />} />
        <Route path="/organization" element={<OrganizationPage />} />
      </Route>
      {/* Styled 404 for unmatched routes (previously redirected to "/"). */}
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
    </ErrorBoundary>
  );
}
