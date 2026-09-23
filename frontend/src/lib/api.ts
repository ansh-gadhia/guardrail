import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from "axios";

// The access token lives only in memory (never localStorage) to limit XSS blast
// radius; the refresh token is an HttpOnly cookie the browser sends automatically.
let accessToken: string | null = null;
let onAuthLost: (() => void) | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}
export function getAccessToken(): string | null {
  return accessToken;
}
export function setOnAuthLost(fn: () => void): void {
  onAuthLost = fn;
}

export const api: AxiosInstance = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) {
    config.headers.set("Authorization", `Bearer ${accessToken}`);
  }
  return config;
});

// refreshSession is the ONE way this app refreshes, and it never runs twice at
// once — not within a tab, and not across tabs.
//
// Refresh tokens rotate, and presenting one that has already been rotated is
// treated as theft: the server revokes the whole family and signs the person out.
// That is the right rule, and it made every concurrent refresh a forced logout.
// Two things were racing:
//
//   - Within a tab. Page-load bootstrap called /auth/refresh directly, while the
//     401 handler used a separate single-flight lock. A request fired before the
//     bootstrap finished hit 401 and started a SECOND refresh with the same cookie.
//   - Across tabs. The cookie is shared, so two tabs loading together — a browser
//     restoring its session — each refreshed with the same token.
//
// Either way the second request presented a token the first had just rotated.
// This deployment's audit log held 35 refresh failures and every one was
// refresh_reuse — 35 people signed out by their own browser.
//
// So: one in-tab promise, and the Web Locks API for mutual exclusion between
// tabs. A tab that waits on the lock refreshes afterwards with the cookie the
// first tab already rotated, which is a clean rotation rather than a reuse. The
// server's reuse detection is left exactly as strict as it was — this removes the
// false positives instead of widening a window for real ones.
let refreshing: Promise<TokenResponseShape | null> | null = null;

interface TokenResponseShape {
  access_token: string;
  [k: string]: unknown;
}

async function doRefresh(): Promise<TokenResponseShape | null> {
  try {
    const r = await axios.post<TokenResponseShape>("/api/v1/auth/refresh", {}, { withCredentials: true });
    accessToken = r.data.access_token;
    return r.data;
  } catch {
    return null;
  }
}

export function refreshSession(): Promise<TokenResponseShape | null> {
  if (!refreshing) {
    // Web Locks needs a secure context and a modern browser; the console is
    // always served over HTTPS, but a browser without it still gets the in-tab
    // guarantee rather than nothing.
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    const run = locks ? locks.request("guardrail-auth-refresh", () => doRefresh()) : doRefresh();
    refreshing = run.finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

// On a 401 for a protected call, attempt a single silent refresh; if that fails,
// surface auth loss so the app can route back to the login screen.
async function tryRefresh(): Promise<boolean> {
  return (await refreshSession()) !== null;
}

api.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & { _retried?: boolean };
    const url = original?.url ?? "";
    const isAuthCall = url.includes("/auth/login") || url.includes("/auth/refresh") || url.includes("/auth/mfa");
    if (error.response?.status === 401 && original && !original._retried && !isAuthCall) {
      original._retried = true;
      if (await tryRefresh()) {
        original.headers.set("Authorization", `Bearer ${accessToken}`);
        return api(original);
      }
      onAuthLost?.();
    }
    return Promise.reject(error);
  },
);

// problemDetail extracts a human message from an RFC 9457 problem+json body.
export function problemDetail(err: unknown, fallback = "Something went wrong"): string {
  const ax = err as AxiosError<{ detail?: string; title?: string }>;
  return ax.response?.data?.detail || ax.response?.data?.title || ax.message || fallback;
}
