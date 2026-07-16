import { create } from "zustand";
import { api, setAccessToken } from "@/lib/api";
import type { LoginResult, Principal, TokenResponse } from "@/lib/types";

interface AuthState {
  principal: Principal | null;
  ready: boolean; // initial session probe finished
  // firstRunDone marks the two-factor offer as dismissed for this sign-in. It is
  // per-session on purpose: "later" should mean later, not never, so the offer
  // returns next time rather than nagging on every navigation now.
  firstRunDone: boolean;
  skipFirstRun: () => void;
  setSession: (t: TokenResponse) => void;
  clear: () => void;
  login: (email: string, password: string, organization?: string) => Promise<LoginResult>;
  verifyMFA: (mfaToken: string, code: string) => Promise<TokenResponse>;
  ldapLogin: (username: string, password: string) => Promise<TokenResponse>;
  bootstrap: () => Promise<void>;
  logout: () => Promise<void>;
  changePassword: (current: string, next: string) => Promise<void>;
  has: (permission: string) => boolean;
}

export const useAuth = create<AuthState>((set, get) => ({
  principal: null,
  ready: false,
  firstRunDone: false,

  skipFirstRun: () => set({ firstRunDone: true }),

  setSession: (t) => {
    setAccessToken(t.access_token);
    set({ principal: t.principal });
  },

  clear: () => {
    setAccessToken(null);
    set({ principal: null, firstRunDone: false });
  },

  login: async (email, password, organization) => {
    const { data } = await api.post<LoginResult>("/auth/login", { email, password, organization });
    if (!(data as { mfa_required?: boolean }).mfa_required) {
      get().setSession(data as TokenResponse);
    }
    return data;
  },

  verifyMFA: async (mfaToken, code) => {
    const { data } = await api.post<TokenResponse>("/auth/mfa/verify", { mfa_token: mfaToken, code });
    get().setSession(data);
    return data;
  },

  ldapLogin: async (username, password) => {
    const { data } = await api.post<TokenResponse>("/auth/ldap/login", { username, password });
    get().setSession(data);
    return data;
  },

  // bootstrap tries to restore a session from the refresh cookie on app load.
  bootstrap: async () => {
    try {
      const { data } = await api.post<TokenResponse>("/auth/refresh", {});
      get().setSession(data);
    } catch {
      get().clear();
    } finally {
      set({ ready: true });
    }
  },

  logout: async () => {
    try {
      await api.post("/auth/logout", {});
    } catch {
      /* ignore */
    }
    get().clear();
  },

  // changePassword rotates the local password. The API revokes all other sessions
  // and returns a fresh token pair so this browser stays signed in.
  changePassword: async (current, next) => {
    const { data } = await api.post<TokenResponse>("/auth/change-password", {
      current_password: current,
      new_password: next,
    });
    get().setSession(data);
  },

  has: (permission) => {
    const p = get().principal;
    if (!p) return false;
    // A user with no roles has no permissions; tolerate a missing list rather
    // than taking the whole console down over it.
    return p.is_super_admin || (p.permissions ?? []).includes(permission);
  },
}));
