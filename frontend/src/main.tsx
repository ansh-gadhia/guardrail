import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { rememberSignOut, setOnAuthLost, signOutExplained } from "./lib/api";
import { idleReason, watchIdle } from "./lib/idle";
import { useAuth } from "./store/auth";
import { Toaster, toast } from "./components/Toast";
import "./store/theme"; // applies the persisted theme before first paint
import "./fonts.css";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 15_000 },
  },
});

// When a refresh ultimately fails, clear the session (route guards redirect to
// login) and surface a session-timeout toast. Guarded so it only fires once for
// an actually-authenticated user, not on the initial bootstrap probe.
setOnAuthLost(() => {
  // No toast when the sign-in page is about to say why, in full.
  if (useAuth.getState().principal && !signOutExplained()) {
    toast.warn("Session expired", "Please sign in again to continue.");
  }
  useAuth.getState().clear();
});

// Nobody has touched any tab of this console for the idle limit: sign out, on
// the server as well, and let the sign-in page say why.
watchIdle(() => {
  if (!useAuth.getState().principal) return;
  rememberSignOut(idleReason());
  void useAuth.getState().logout(true);
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
        <Toaster />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
