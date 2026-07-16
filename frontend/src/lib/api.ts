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

// On a 401 for a protected call, attempt a single silent refresh; if that fails,
// surface auth loss so the app can route back to the login screen.
let refreshing: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = axios
      .post("/api/v1/auth/refresh", {}, { withCredentials: true })
      .then((r) => {
        accessToken = r.data.access_token as string;
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  }
  return refreshing;
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
