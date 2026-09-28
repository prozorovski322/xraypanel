import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { api, ApiError, onSessionEnded, refreshSession, setAccessToken, unwrap, type LoginResponse } from "@/api/client";

export interface Me {
  kind?: "admin" | "api_key";
  username?: string;
  role?: "superadmin" | "admin" | "viewer";
  scopes?: string[];
}

type Status = "restoring" | "anonymous" | "authenticated";

/** The result of a password step: either signed in, or a second factor is needed. */
export type LoginStep = { kind: "done" } | { kind: "mfa"; mfaToken: string };

interface AuthContextValue {
  status: Status;
  me: Me | null;
  login(username: string, password: string): Promise<LoginStep>;
  completeMfa(mfaToken: string, code: string): Promise<void>;
  logout(): Promise<void>;
  /** can reports whether the signed-in administrator's role covers a scope. */
  can(scope: string): boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Mirrors auth.RoleAllows on the panel. Only used to hide controls that would be refused:
// the panel enforces the same rule on every request, so this is convenience, not security.
function roleAllows(role: Me["role"], scope: string): boolean {
  if (role === "superadmin" || role === "admin") return true;
  if (role === "viewer") return !scope.endsWith(":write");
  return false;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("restoring");
  const [me, setMe] = useState<Me | null>(null);
  const queryClient = useQueryClient();

  const loadMe = useCallback(async () => {
    const result = await api.GET("/auth/me");
    const body = unwrap(result) as Me;
    setMe(body);
    setStatus("authenticated");
  }, []);

  const accept = useCallback(
    async (response: LoginResponse) => {
      if (!response.access_token) throw new Error("the panel did not issue a session");
      setAccessToken(response.access_token);
      await loadMe();
    },
    [loadMe],
  );

  // A reload restores the session from the refresh cookie, which the page cannot read and
  // does not need to: one call either returns an access token or says there is no session.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const restored = await refreshSession();
      if (cancelled) return;
      if (!restored) {
        setStatus("anonymous");
        return;
      }
      try {
        await loadMe();
      } catch {
        if (!cancelled) setStatus("anonymous");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loadMe]);

  // Any request that finds the session gone sends the app back to the login screen, and
  // everything cached for the previous session is dropped: the next administrator to sign
  // in on this browser must not see a flash of the last one's data.
  useEffect(
    () =>
      onSessionEnded(() => {
        setMe(null);
        setStatus("anonymous");
        queryClient.clear();
      }),
    [queryClient],
  );

  const login = useCallback(
    async (username: string, password: string): Promise<LoginStep> => {
      const result = await api.POST("/auth/login", { body: { username, password } });
      const body = unwrap(result);
      if (body.mfa_required) {
        if (!body.mfa_token) throw new Error("the panel asked for a code but sent no ticket");
        return { kind: "mfa", mfaToken: body.mfa_token };
      }
      await accept(body);
      return { kind: "done" };
    },
    [accept],
  );

  const completeMfa = useCallback(
    async (mfaToken: string, code: string) => {
      const result = await api.POST("/auth/login/mfa", { body: { mfa_token: mfaToken, code } });
      await accept(unwrap(result));
    },
    [accept],
  );

  const logout = useCallback(async () => {
    try {
      await api.POST("/auth/logout");
    } catch (error) {
      // Signing out locally still happens: a panel that cannot be reached must not trap
      // somebody in a session they are trying to leave.
      if (!(error instanceof ApiError)) console.warn("logout request failed", error);
    }
    setAccessToken(null);
    setMe(null);
    setStatus("anonymous");
    queryClient.clear();
  }, [queryClient]);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      me,
      login,
      completeMfa,
      logout,
      can: (scope) => (me?.kind === "api_key" ? (me.scopes ?? []).includes(scope) : roleAllows(me?.role, scope)),
    }),
    [status, me, login, completeMfa, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
