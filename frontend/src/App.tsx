import { useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./store/auth";
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
import { FirstRunPage } from "./pages/FirstRunPage";
import { NotFoundPage, ErrorBoundary } from "./pages/ErrorPages";

function RequireAuth({ children }: { children: JSX.Element }) {
  const { principal, ready, firstRunDone } = useAuth();
  const location = useLocation();
  if (!ready) return <FullScreenSpinner />;
  if (!principal) return <Navigate to="/login" state={{ from: location }} replace />;
  // A temporary password must be replaced before anything else. Gating here
  // rather than on a route means it cannot be walked around by typing a URL.
  if (principal.must_change_password && !firstRunDone) return <FirstRunPage />;
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
        <Route path="/security" element={<SecurityPage />} />
      </Route>
      {/* Styled 404 for unmatched routes (previously redirected to "/"). */}
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
    </ErrorBoundary>
  );
}
