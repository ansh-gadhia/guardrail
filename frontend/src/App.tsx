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
// Two reasons, and they arrive by different doors:
//
//   * a temporary password somebody else typed, which must be replaced; and
//   * a federated account with no second factor.
//
// The second exists because an account provisioned by the SIEM never has the
// first. It has no password, so must_change_password is false and the whole
// first-run flow — including the two-factor offer at the end of it — was simply
// skipped. Every analyst arriving through single sign-on went straight into the
// console having never been asked, which is the opposite of the intent: they are
// precisely the people the console reaches privileged devices on behalf of.
//
// Local accounts are deliberately not included. Somebody who has been signing in
// with a password for a year and chose not to enrol has already answered this
// question; turning that into a prompt on every sign-in is how people learn to
// click past security dialogs.
function needsFirstRun(principal: Principal, firstRunDone: boolean): boolean {
  if (firstRunDone) return false;
  if (principal.must_change_password) return true;
  return principal.auth_provider === "siem" && !principal.mfa_enabled;
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
